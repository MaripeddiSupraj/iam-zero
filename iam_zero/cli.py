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
@click.version_option(package_name="iam-zero")
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
# scan aws
# ---------------------------------------------------------------------------

@scan.command("aws")
@click.option("--role", "role_arn", required=True, help="IAM role ARN to scan")
@click.option("--days", default=90, show_default=True, help="Look-back window in days")
@click.option("--profile", default=None, help="AWS profile name")
@click.option("--dry-run", is_flag=True, default=False,
              help="Print findings to terminal only (default if no output flag given)")
@click.option("--output", "output_path", default=None, metavar="PATH",
              help="Write recommended policy JSON to this file")
@click.option("--github", "open_github_pr", is_flag=True, default=False,
              help="Open a GitHub PR (requires token + repo in config)")
def scan_aws(role_arn, days, profile, dry_run, output_path, open_github_pr):
    """Scan an AWS IAM role and output a least-privilege policy.

    Default (no flags): dry-run — prints findings to terminal, no side effects.
    """
    cfg = load_config()
    mode = resolve_output_mode(dry_run, output_path, open_github_pr)

    # Validate GitHub config before any expensive API calls
    github_token = None
    target_repo = None
    if mode.github:
        try:
            github_token = get_github_token(cfg)
        except ValueError as e:
            print_error(str(e))
            sys.exit(1)
        target_repo = cfg.get("github", {}).get("default_repo", "")
        if not target_repo:
            print_error(
                "No GitHub repo configured.\n"
                "  Run: iam-zero configure"
            )
            sys.exit(1)

    print_banner("AWS", role_arn, days, _mode_label(mode))

    # 1. Fetch CloudTrail events
    try:
        from .aws.cloudtrail import fetch_used_actions
        with scan_step("Reading CloudTrail events") as detail:
            used_actions = fetch_used_actions(role_arn, days, profile=profile)
            detail(f"[{len(used_actions):,} unique actions]")
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching CloudTrail events\n  {e}")
        sys.exit(1)

    # 2. Fetch current IAM policies
    try:
        from .aws.iam_analyzer import get_role_policies, compute_unused
        with scan_step("Fetching IAM role policies") as detail:
            current_actions, raw_docs = get_role_policies(role_arn, profile=profile)
            detail(f"[{len(current_actions)} actions in policy]")
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching IAM policies\n  {e}")
        sys.exit(1)

    unused_actions = compute_unused(current_actions, used_actions)
    active_actions = [a for a in current_actions if a in used_actions]

    if not unused_actions:
        print_success("No unused permissions found — this role looks well-scoped already.")
        sys.exit(0)

    # 3. Claude analysis
    try:
        api_key = get_anthropic_api_key(cfg)
        ai = anthropic.Anthropic(api_key=api_key)
        from .agent.analyst import analyze_aws_permissions
        with scan_step("Claude reasoning about safe removals") as detail:
            findings = analyze_aws_permissions(
                ai, role_arn, current_actions, list(used_actions), unused_actions, days
            )
            detail("Analysis complete")
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Claude analysis failed\n  {e}")
        sys.exit(1)

    console.print()

    # 4. Display findings
    print_findings_table(findings, active_actions, item_label="Permission")

    # 5. Generate policies
    from .aws.policy_generator import generate_minimal_policy
    current_policy_json = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [s for doc in raw_docs for s in doc.get("Statement", [])],
        },
        indent=2,
    )
    new_policy_json = generate_minimal_policy(used_actions, findings, raw_docs)

    # 6. Output
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
        title = f"fix(iam): tighten permissions for {role_short} [aws]"
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
            print_pr_opened(pr_url, title, is_new=is_new)
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
# scan gcp
# ---------------------------------------------------------------------------

@scan.command("gcp")
@click.option("--service-account", "service_account", required=True,
              help="Service account email")
@click.option("--project", required=True, help="GCP project ID")
@click.option("--days", default=90, show_default=True)
@click.option("--dry-run", is_flag=True, default=False,
              help="Print findings to terminal only (default if no output flag given)")
@click.option("--output", "output_path", default=None, metavar="PATH",
              help="Write recommended policy JSON to this file")
@click.option("--github", "open_github_pr", is_flag=True, default=False,
              help="Open a GitHub PR (requires token + repo in config)")
def scan_gcp(service_account, project, days, dry_run, output_path, open_github_pr):
    """Scan a GCP service account and output a least-privilege policy.

    Default (no flags): dry-run — prints findings to terminal, no side effects.
    """
    cfg = load_config()
    mode = resolve_output_mode(dry_run, output_path, open_github_pr)

    # Validate GitHub config before any expensive API calls
    github_token = None
    target_repo = None
    if mode.github:
        try:
            github_token = get_github_token(cfg)
        except ValueError as e:
            print_error(str(e))
            sys.exit(1)
        target_repo = cfg.get("github", {}).get("default_repo", "")
        if not target_repo:
            print_error(
                "No GitHub repo configured.\n"
                "  Run: iam-zero configure"
            )
            sys.exit(1)

    print_banner("GCP", service_account, days, _mode_label(mode), project=project)

    # 1. Fetch IAM role bindings
    try:
        from .gcp.iam_analyzer import get_service_account_roles, compute_unused_roles
        with scan_step("Fetching IAM role bindings") as detail:
            current_roles = get_service_account_roles(service_account, project)
            detail(f"[{len(current_roles)} roles]")
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching IAM bindings\n  {e}")
        sys.exit(1)

    # 2. Fetch Cloud Audit Logs
    try:
        from .gcp.audit_logs import fetch_used_methods
        with scan_step("Reading Cloud Audit Logs") as detail:
            used_methods = fetch_used_methods(service_account, project, days)
            detail(f"[{len(used_methods):,} unique methods]")
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching Cloud Audit Logs\n  {e}")
        sys.exit(1)

    unused_roles = compute_unused_roles(current_roles, used_methods)
    active_roles = [r for r in current_roles if r not in set(unused_roles)]

    if not unused_roles:
        print_success("No unused roles found — this service account looks well-scoped.")
        sys.exit(0)

    # 3. Claude analysis
    try:
        api_key = get_anthropic_api_key(cfg)
        ai = anthropic.Anthropic(api_key=api_key)
        from .agent.analyst import analyze_gcp_permissions
        with scan_step("Claude reasoning about safe removals") as detail:
            findings = analyze_gcp_permissions(
                ai, service_account, current_roles, list(used_methods), unused_roles, days
            )
            detail("Analysis complete")
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Claude analysis failed\n  {e}")
        sys.exit(1)

    console.print()

    # 4. Display findings
    print_findings_table(findings, active_roles, item_label="Role")

    # 5. Generate bindings
    from .gcp.policy_generator import generate_minimal_bindings
    current_bindings_json = json.dumps(
        {"serviceAccount": service_account, "currentRoles": current_roles}, indent=2
    )
    new_bindings_json = generate_minimal_bindings(service_account, current_roles, findings)

    # 6. Output
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
        title = f"fix(iam): tighten permissions for {sa_short} [gcp]"
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
            print_pr_opened(pr_url, title, is_new=is_new)
        except RuntimeError as e:
            print_error(str(e))
            sys.exit(1)

    print_summary_panel(
        findings, active_roles, "gcp", service_account, project,
        is_dry_run=mode.is_dry_run,
        has_file=bool(mode.file_path),
        has_github=mode.github,
    )
