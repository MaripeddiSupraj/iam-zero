import json
import sys

import click
import anthropic

from .shared.config import load_config, save_config, get_github_token, get_anthropic_api_key
from .shared.output import resolve_output_mode, write_policy_file
from .shared.report import (
    console,
    print_banner,
    scan_step,
    print_findings_table,
    print_summary_panel,
    print_file_written,
    print_pr_opened,
    print_policy_terminal,
    print_success,
    print_error,
)


def _mode_label(mode) -> str:
    if mode.is_dry_run:
        return "dry-run"
    parts = []
    if mode.file_path:
        parts.append(f"--output {mode.file_path}")
    if mode.github:
        parts.append("--github")
    return " + ".join(parts) if parts else "dry-run"


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="zero-iam")
def cli():
    """iam-zero — detect overpermissive IAM roles and auto-open least-privilege PRs."""


@cli.command()
def configure():
    """Interactive setup: Anthropic key (required) + GitHub token/repo (optional, only for --github)."""
    cfg = load_config()
    console.print("[bold]iam-zero configuration[/bold]\n")

    anthropic_key = click.prompt(
        "Anthropic API key",
        default=cfg.get("anthropic", {}).get("api_key", ""),
        hide_input=True,
    )

    console.print("\n  [dim]GitHub is only needed for --github (open PRs). Press Enter to skip.[/dim]")
    github_token = click.prompt(
        "GitHub Personal Access Token (repo scope) [optional]",
        default=cfg.get("github", {}).get("token", ""),
        hide_input=True,
    )
    default_repo = click.prompt(
        "Default GitHub repo for PRs (owner/repo) [optional]",
        default=cfg.get("github", {}).get("default_repo", ""),
    )

    cfg["anthropic"] = {"api_key": anthropic_key}
    cfg["github"] = {"token": github_token, "default_repo": default_repo}
    save_config(cfg)
    print_success("Configuration saved to ~/.iam-zero/config.toml")


# ---------------------------------------------------------------------------
# auth test
# ---------------------------------------------------------------------------

@cli.group()
def auth():
    """Test and manage authentication."""


@auth.command("test")
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--project", default=None, help="GCP project ID")
def auth_test(profile, project):
    """Verify cloud credentials.

    Pass --project to test GCP. Pass --profile to test a specific AWS profile.
    If neither is passed, both clouds are tested.
    """
    test_aws = profile is not None or project is None
    test_gcp = project is not None

    if test_aws:
        try:
            import boto3
            session = boto3.Session(profile_name=profile)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            print_success(f"AWS authenticated as {identity['Arn']}")
        except Exception as e:
            print_error(f"AWS authentication failed\n  {e}")

    if test_gcp:
        try:
            from google.cloud import resourcemanager_v3
            rm = resourcemanager_v3.ProjectsClient()
            proj = rm.get_project(name=f"projects/{project}")
            print_success(f"GCP authenticated — project: {proj.display_name} ({project})")
        except Exception as e:
            print_error(
                f"GCP authentication failed\n"
                f"  {e}\n"
                f"  Fix: run  gcloud auth application-default login\n"
                f"  Docs: https://github.com/MaripeddiSupraj/iam-zero#gcp-auth"
            )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.group()
def scan():
    """Scan IAM roles for overpermissioning."""


# ---------------------------------------------------------------------------
# shared scan helpers
# ---------------------------------------------------------------------------

def _validate_github(cfg, mode) -> tuple[str, str]:
    """Returns (token, target_repo). Exits on misconfiguration."""
    if not mode.github:
        return None, None
    try:
        token = get_github_token(cfg)
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)
    repo = cfg.get("github", {}).get("default_repo", "")
    if not repo:
        print_error(
            "No GitHub repo configured.\n"
            "  Run: iam-zero configure"
        )
        sys.exit(1)
    return token, repo


def _print_bulk_header(cloud: str, identities: list[str], days: int, mode_label: str, project=None):
    console.print()
    console.print(f"[bold cyan]╭─{'─'*56}╮[/bold cyan]")
    console.print(f"[bold cyan]│[/bold cyan]  [bold]iam-zero ⚡  Bulk {cloud.upper()} Scan[/bold]{' ' * (37 - len(cloud))}[bold cyan]│[/bold cyan]")
    console.print(f"[bold cyan]╰─{'─'*56}╯[/bold cyan]")
    console.print(f"  [bold]Provider[/bold]   {cloud.upper()}")
    console.print(f"  [bold]Identities[/bold] {len(identities)} found")
    if project:
        console.print(f"  [bold]Project[/bold]   {project}")
    console.print(f"  [bold]Lookback[/bold]  {days} days")
    console.print(f"  [bold]Mode[/bold]      {mode_label}")
    console.print()


# ---------------------------------------------------------------------------
# AWS scan
# ---------------------------------------------------------------------------

def _scan_aws_role(role_arn, days, profile, region, no_access_advisor, cfg, mode, ai, github_token, target_repo):
    """Run the full scan pipeline for a single AWS role. Returns (role_arn, findings, active_actions, raw_docs, current_actions, used_actions) or None on unrecoverable error."""
    from .aws.cloudtrail import fetch_used_actions
    from .aws.iam_analyzer import get_role_policies, compute_unused
    from .aws.access_advisor import fetch_service_last_accessed, protect_active_services
    from .aws.policy_generator import generate_minimal_policy
    from .agent.analyst import analyze_aws_permissions

    with scan_step(f"CloudTrail — {role_arn.split('/')[-1]}") as detail:
        used_actions = fetch_used_actions(role_arn, days, profile=profile, region=region)
        detail(f"[{len(used_actions):,} actions]")

    with scan_step(f"IAM policies — {role_arn.split('/')[-1]}") as detail:
        current_actions, raw_docs = get_role_policies(role_arn, profile=profile)
        detail(f"[{len(current_actions)} actions in policy]")

    unused_actions = compute_unused(current_actions, used_actions)
    active_actions = [a for a in current_actions if a in used_actions]

    protected_actions: dict[str, str] = {}
    if not no_access_advisor and unused_actions:
        try:
            with scan_step(f"Access Advisor — {role_arn.split('/')[-1]}") as detail:
                service_last_accessed = fetch_service_last_accessed(role_arn, profile=profile)
                unused_actions, protected_actions = protect_active_services(
                    unused_actions, service_last_accessed
                )
                detail(f"[{len(protected_actions)} protected]")
            unused_actions = sorted(set(unused_actions) | set(protected_actions))
        except (PermissionError, Exception):
            pass

    if not unused_actions:
        console.print(f"  [dim]✓ {role_arn.split('/')[-1]} — well-scoped, nothing to tighten[/dim]")
        return None

    with scan_step(f"Claude — {role_arn.split('/')[-1]}") as detail:
        findings = analyze_aws_permissions(
            ai, role_arn, current_actions, list(used_actions), unused_actions, days,
            protected_actions=protected_actions,
        )
        detail("done")

    current_policy_json = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [s for doc in raw_docs for s in doc.get("Statement", [])],
        },
        indent=2,
    )
    new_policy_json = generate_minimal_policy(used_actions, findings, raw_docs)

    if mode.file_path:
        try:
            write_policy_file(mode.file_path, new_policy_json)
            print_file_written(mode.file_path, "aws", identity=role_arn)
        except OSError as e:
            print_error(f"Failed to write policy file\n  {e}")

    if mode.github:
        role_short = role_arn.split("/")[-1]
        try:
            from .shared.pr import open_pr
            pr_url, is_new = open_pr(
                github_token=github_token,
                repo_name=target_repo,
                cloud="aws",
                identity=role_arn,
                identity_short=role_short,
                findings=findings,
                current_policy=current_policy_json,
                new_policy=new_policy_json,
                days=days,
                branch_name=f"iam-zero/aws-{role_short}",
            )
            print_pr_opened(pr_url, f"fix(iam): tighten permissions for {role_short} [aws]", is_new=is_new)
        except RuntimeError as e:
            print_error(str(e))

    return (role_arn, findings, active_actions, raw_docs, current_actions, used_actions)


@scan.command("aws")
@click.option("--role", "role_arn", default=None, help="IAM role ARN to scan")
@click.option("--all-roles", is_flag=True, default=False, help="Scan every IAM role in the account")
@click.option("--days", default=90, show_default=True, help="Look-back window in days")
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--region", default=None,
              help="AWS region for CloudTrail lookup (LookupEvents is per-region)")
@click.option("--no-access-advisor", is_flag=True, default=False,
              help="Skip the IAM Access Advisor corroboration step")
@click.option("--dry-run", is_flag=True, default=False,
              help="Print findings to terminal only (default if no output flag given)")
@click.option("--output", "output_path", default=None, metavar="PATH",
              help="Write recommended policy JSON to this file")
@click.option("--github", "open_github_pr", is_flag=True, default=False,
              help="Open a GitHub PR (requires token + repo in config)")
def scan_aws(role_arn, all_roles, days, profile, region, no_access_advisor, dry_run, output_path, open_github_pr):
    """Scan AWS IAM roles and output least-privilege policies.

    Pass --role for a single role, or --all-roles to scan every role in the account.

    Default (no flags): dry-run — prints findings to terminal, no side effects.
    """
    if not role_arn and not all_roles:
        print_error("Pass --role <arn> to scan one role, or --all-roles to scan all roles in the account")
        sys.exit(1)
    if role_arn and all_roles:
        print_error("Use either --role or --all-roles, not both")
        sys.exit(1)

    cfg = load_config()
    mode = resolve_output_mode(dry_run, output_path, open_github_pr)
    github_token, target_repo = _validate_github(cfg, mode)
    api_key = get_anthropic_api_key(cfg)
    ai = anthropic.Anthropic(api_key=api_key)

    if all_roles:
        from .aws.iam_analyzer import list_roles
        with scan_step("Listing all IAM roles") as detail:
            identities = list_roles(profile=profile)
            detail(f"[{len(identities)} roles found]")
        _print_bulk_header("AWS", identities, days, _mode_label(mode))
        results = []
        for arn in identities:
            r = _scan_aws_role(arn, days, profile, region, no_access_advisor, cfg, mode, ai, github_token, target_repo)
            if r:
                results.append(r)
        if not results:
            print_success("No roles need tightening — all well-scoped.")
            return
        console.print(f"\n  [bold]Summary:[/bold] {len(results)} role(s) with tightening opportunities\n")
        for (arn, findings, active, *_rest) in results:
            to_remove = sum(1 for f in findings if f.get("recommendation", "").lower() == "remove")
            console.print(f"  [bold]{arn.split('/')[-1]}[/bold] — {len(findings)} unused, {to_remove} removable")
        return

    # Single role
    github_token, target_repo = _validate_github(cfg, mode)

    print_banner("AWS", role_arn, days, _mode_label(mode))

    from .aws.cloudtrail import fetch_used_actions
    with scan_step("Reading CloudTrail events") as detail:
        used_actions = fetch_used_actions(role_arn, days, profile=profile, region=region)
        detail(f"[{len(used_actions):,} unique actions]")

    from .aws.iam_analyzer import get_role_policies, compute_unused
    with scan_step("Fetching IAM role policies") as detail:
        current_actions, raw_docs = get_role_policies(role_arn, profile=profile)
        detail(f"[{len(current_actions)} actions in policy]")

    unused_actions = compute_unused(current_actions, used_actions)
    active_actions = [a for a in current_actions if a in used_actions]

    if not unused_actions:
        print_success("No unused permissions found — this role looks well-scoped already.")
        sys.exit(0)

    protected_actions: dict[str, str] = {}
    if not no_access_advisor:
        try:
            from .aws.access_advisor import fetch_service_last_accessed, protect_active_services
            with scan_step("Corroborating with IAM Access Advisor") as detail:
                service_last_accessed = fetch_service_last_accessed(role_arn, profile=profile)
                unused_actions, protected_actions = protect_active_services(
                    unused_actions, service_last_accessed
                )
                detail(f"[{len(protected_actions)} action(s) protected by service activity]")
            unused_actions = sorted(set(unused_actions) | set(protected_actions))
        except PermissionError as e:
            console.print("  [yellow]⚠  Access Advisor unavailable — continuing without it[/yellow]")
            console.print(f"  [dim]{e}[/dim]")
        except Exception as e:
            console.print(f"  [yellow]⚠  Access Advisor failed ({e}) — continuing without it[/yellow]")

    from .agent.analyst import analyze_aws_permissions
    with scan_step("Claude reasoning about safe removals") as detail:
        findings = analyze_aws_permissions(
            ai, role_arn, current_actions, list(used_actions), unused_actions, days,
            protected_actions=protected_actions,
        )
        detail("Analysis complete")

    console.print()
    print_findings_table(findings, active_actions, item_label="Permission")

    from .aws.policy_generator import generate_minimal_policy
    current_policy_json = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [s for doc in raw_docs for s in doc.get("Statement", [])],
        },
        indent=2,
    )
    new_policy_json = generate_minimal_policy(used_actions, findings, raw_docs)

    if mode.is_dry_run:
        print_policy_terminal(current_policy_json, new_policy_json)
        print_summary_panel(
            findings, active_actions, "aws", role_arn, None,
            is_dry_run=True, has_file=False, has_github=False,
        )
        sys.exit(0)

    if mode.file_path:
        try:
            write_policy_file(mode.file_path, new_policy_json)
            print_file_written(mode.file_path, "aws", identity=role_arn)
        except OSError as e:
            print_error(f"Failed to write policy file\n  {e}")
            sys.exit(1)

    if mode.github:
        role_short = role_arn.split("/")[-1]
        try:
            from .shared.pr import open_pr
            pr_url, is_new = open_pr(
                github_token=github_token,
                repo_name=target_repo,
                cloud="aws",
                identity=role_arn,
                identity_short=role_short,
                findings=findings,
                current_policy=current_policy_json,
                new_policy=new_policy_json,
                days=days,
                branch_name=f"iam-zero/aws-{role_short}",
            )
            print_pr_opened(pr_url, f"fix(iam): tighten permissions for {role_short} [aws]", is_new=is_new)
        except RuntimeError as e:
            print_error(str(e))
            sys.exit(1)

    print_summary_panel(
        findings, active_actions, "aws", role_arn, None,
        is_dry_run=mode.is_dry_run,
        has_file=bool(mode.file_path),
        has_github=mode.github,
    )


# ---------------------------------------------------------------------------
# GCP scan
# ---------------------------------------------------------------------------

def _scan_gcp_sa(service_account, project, days, cfg, mode, ai, github_token, target_repo):
    """Run the full scan pipeline for a single GCP service account."""
    from .gcp.iam_analyzer import get_service_account_roles, compute_unused_roles
    from .gcp.audit_logs import fetch_used_methods
    from .gcp.policy_generator import generate_minimal_bindings
    from .agent.analyst import analyze_gcp_permissions

    sa_short = service_account.split("@")[0]

    with scan_step(f"IAM bindings — {sa_short}") as detail:
        current_roles = get_service_account_roles(service_account, project)
        detail(f"[{len(current_roles)} roles]")

    with scan_step(f"Audit Logs — {sa_short}") as detail:
        used_methods = fetch_used_methods(service_account, project, days)
        detail(f"[{len(used_methods):,} methods]")

    unused_roles = compute_unused_roles(current_roles, used_methods)
    active_roles = [r for r in current_roles if r not in set(unused_roles)]

    if not unused_roles:
        console.print(f"  [dim]✓ {sa_short} — well-scoped, nothing to tighten[/dim]")
        return None

    with scan_step(f"Claude — {sa_short}") as detail:
        findings = analyze_gcp_permissions(
            ai, service_account, current_roles, list(used_methods), unused_roles, days
        )
        detail("done")

    current_bindings_json = json.dumps(
        {"serviceAccount": service_account, "currentRoles": current_roles}, indent=2
    )
    new_bindings_json = generate_minimal_bindings(service_account, current_roles, findings)

    if mode.file_path:
        try:
            write_policy_file(mode.file_path, new_bindings_json)
            print_file_written(mode.file_path, "gcp", project=project, identity=service_account)
        except OSError as e:
            print_error(f"Failed to write policy file\n  {e}")

    if mode.github:
        try:
            from .shared.pr import open_pr
            pr_url, is_new = open_pr(
                github_token=github_token,
                repo_name=target_repo,
                cloud="gcp",
                identity=service_account,
                identity_short=sa_short,
                findings=findings,
                current_policy=current_bindings_json,
                new_policy=new_bindings_json,
                days=days,
                branch_name=f"iam-zero/gcp-{sa_short}",
            )
            print_pr_opened(pr_url, f"fix(iam): tighten permissions for {sa_short} [gcp]", is_new=is_new)
        except RuntimeError as e:
            print_error(str(e))

    return (service_account, findings, active_roles, current_roles, used_methods)


@scan.command("gcp")
@click.option("--service-account", "service_account", default=None, help="Service account email")
@click.option("--all-service-accounts", is_flag=True, default=False, help="Scan all service accounts in the project")
@click.option("--project", required=True, help="GCP project ID")
@click.option("--days", default=90, show_default=True)
@click.option("--dry-run", is_flag=True, default=False,
              help="Print findings to terminal only (default if no output flag given)")
@click.option("--output", "output_path", default=None, metavar="PATH",
              help="Write recommended policy JSON to this file")
@click.option("--github", "open_github_pr", is_flag=True, default=False,
              help="Open a GitHub PR (requires token + repo in config)")
def scan_gcp(service_account, all_service_accounts, project, days, dry_run, output_path, open_github_pr):
    """Scan GCP service accounts and output least-privilege policies.

    Pass --service-account for one SA, or --all-service-accounts to scan every SA in the project.

    Default (no flags): dry-run — prints findings to terminal, no side effects.
    """
    if not service_account and not all_service_accounts:
        print_error("Pass --service-account <email> to scan one SA, or --all-service-accounts to scan all")
        sys.exit(1)
    if service_account and all_service_accounts:
        print_error("Use either --service-account or --all-service-accounts, not both")
        sys.exit(1)

    cfg = load_config()
    mode = resolve_output_mode(dry_run, output_path, open_github_pr)
    github_token, target_repo = _validate_github(cfg, mode)
    api_key = get_anthropic_api_key(cfg)
    ai = anthropic.Anthropic(api_key=api_key)

    if all_service_accounts:
        from .gcp.iam_analyzer import list_service_accounts
        with scan_step("Listing all service accounts") as detail:
            identities = list_service_accounts(project)
            detail(f"[{len(identities)} SAs found]")
        _print_bulk_header("GCP", identities, days, _mode_label(mode), project=project)
        results = []
        for sa in identities:
            r = _scan_gcp_sa(sa, project, days, cfg, mode, ai, github_token, target_repo)
            if r:
                results.append(r)
        if not results:
            print_success("No service accounts need tightening — all well-scoped.")
            return
        console.print(f"\n  [bold]Summary:[/bold] {len(results)} service account(s) with tightening opportunities\n")
        for (sa, findings, *_) in results:
            to_remove = sum(1 for f in findings if f.get("recommendation", "").lower() == "remove")
            console.print(f"  [bold]{sa.split('@')[0]}[/bold] — {len(findings)} unused, {to_remove} removable")
        return

    # Single service account
    print_banner("GCP", service_account, days, _mode_label(mode), project=project)

    from .gcp.iam_analyzer import get_service_account_roles, compute_unused_roles
    with scan_step("Fetching IAM role bindings") as detail:
        current_roles = get_service_account_roles(service_account, project)
        detail(f"[{len(current_roles)} roles]")

    from .gcp.audit_logs import fetch_used_methods
    with scan_step("Reading Cloud Audit Logs") as detail:
        used_methods = fetch_used_methods(service_account, project, days)
        detail(f"[{len(used_methods):,} unique methods]")

    unused_roles = compute_unused_roles(current_roles, used_methods)
    active_roles = [r for r in current_roles if r not in set(unused_roles)]

    if not unused_roles:
        print_success("No unused roles found — this service account looks well-scoped.")
        sys.exit(0)

    from .agent.analyst import analyze_gcp_permissions
    with scan_step("Claude reasoning about safe removals") as detail:
        findings = analyze_gcp_permissions(
            ai, service_account, current_roles, list(used_methods), unused_roles, days
        )
        detail("Analysis complete")

    console.print()
    print_findings_table(findings, active_roles, item_label="Role")

    from .gcp.policy_generator import generate_minimal_bindings
    current_bindings_json = json.dumps(
        {"serviceAccount": service_account, "currentRoles": current_roles}, indent=2
    )
    new_bindings_json = generate_minimal_bindings(service_account, current_roles, findings)

    if mode.is_dry_run:
        print_policy_terminal(current_bindings_json, new_bindings_json)
        print_summary_panel(
            findings, active_roles, "gcp", service_account, project,
            is_dry_run=True, has_file=False, has_github=False,
        )
        sys.exit(0)

    if mode.file_path:
        try:
            write_policy_file(mode.file_path, new_bindings_json)
            print_file_written(mode.file_path, "gcp", project=project, identity=service_account)
        except OSError as e:
            print_error(f"Failed to write policy file\n  {e}")
            sys.exit(1)

    if mode.github:
        sa_short = service_account.split("@")[0]
        try:
            from .shared.pr import open_pr
            pr_url, is_new = open_pr(
                github_token=github_token,
                repo_name=target_repo,
                cloud="gcp",
                identity=service_account,
                identity_short=sa_short,
                findings=findings,
                current_policy=current_bindings_json,
                new_policy=new_bindings_json,
                days=days,
                branch_name=f"iam-zero/gcp-{sa_short}",
            )
            print_pr_opened(pr_url, f"fix(iam): tighten permissions for {sa_short} [gcp]", is_new=is_new)
        except RuntimeError as e:
            print_error(str(e))
            sys.exit(1)

    print_summary_panel(
        findings, active_roles, "gcp", service_account, project,
        is_dry_run=mode.is_dry_run,
        has_file=bool(mode.file_path),
        has_github=mode.github,
    )
