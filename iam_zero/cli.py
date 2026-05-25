import json
import sys

import click
import anthropic

from .shared.config import load_config, save_config, get_github_token, get_anthropic_api_key
from .shared.output import resolve_output_mode, write_policy_file
from .shared.report import (
    console,
    print_header,
    print_success,
    print_warning,
    print_error,
    print_info,
    print_permission_table,
    print_dry_run_notice,
    print_policy_terminal,
    print_output_written,
)


@click.group()
@click.version_option(package_name="iam-zero")
def cli():
    """iam-zero — detect overpermissive IAM roles and auto-open least-privilege PRs."""


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------

@cli.command()
def configure():
    """Interactive setup: GitHub token, Anthropic key, default repo."""
    cfg = load_config()
    console.print("[bold]iam-zero configuration[/bold]\n")

    github_token = click.prompt(
        "GitHub Personal Access Token (repo scope)",
        default=cfg.get("github", {}).get("token", ""),
        hide_input=True,
    )
    default_repo = click.prompt(
        "Default GitHub repo for PRs (owner/repo)",
        default=cfg.get("github", {}).get("default_repo", ""),
    )
    anthropic_key = click.prompt(
        "Anthropic API key",
        default=cfg.get("anthropic", {}).get("api_key", ""),
        hide_input=True,
    )

    cfg["github"] = {"token": github_token, "default_repo": default_repo}
    cfg["anthropic"] = {"api_key": anthropic_key}
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
    """Verify AWS + GCP credentials work."""
    try:
        import boto3
        session = boto3.Session(profile_name=profile)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print_success(f"AWS authenticated as {identity['Arn']}")
    except Exception as e:
        print_error(f"AWS authentication failed: {e}")

    if project:
        try:
            from google.cloud import resourcemanager_v3
            rm = resourcemanager_v3.ProjectsClient()
            proj = rm.get_project(name=f"projects/{project}")
            print_success(f"GCP authenticated — project: {proj.display_name} ({project})")
        except Exception as e:
            print_error(f"GCP authentication failed: {e}")
    else:
        print_warning("GCP: pass --project <id> to test GCP auth")


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
              help="Print findings to terminal only (default behaviour if no output flag given)")
@click.option("--output", "output_path", default=None, metavar="PATH",
              help="Write recommended policy JSON to this file")
@click.option("--github", "open_github_pr", is_flag=True, default=False,
              help="Open a GitHub PR (requires token + repo in config)")
def scan_aws(role_arn, days, profile, dry_run, output_path, open_github_pr):
    """Scan an AWS IAM role and output a least-privilege policy.

    Default (no flags): prints findings to terminal. Safe, no side effects.
    """
    cfg = load_config()
    mode = resolve_output_mode(dry_run, output_path, open_github_pr)

    # Validate GitHub config upfront — fail fast before expensive API calls
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

    if mode.is_dry_run:
        print_dry_run_notice()

    print_header(f"iam-zero AWS scan: {role_arn}")

    # 1. Fetch CloudTrail events
    print_info(f"Fetching CloudTrail events for the last {days} days...")
    try:
        from .aws.cloudtrail import fetch_used_actions
        used_actions = fetch_used_actions(role_arn, days, profile=profile)
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching CloudTrail events: {e}")
        sys.exit(1)

    print_success(f"Found {len(used_actions)} unique actions in CloudTrail")

    # 2. Fetch current IAM policies
    print_info("Fetching current IAM policies...")
    try:
        from .aws.iam_analyzer import get_role_policies, compute_unused
        current_actions, raw_docs = get_role_policies(role_arn, profile=profile)
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching IAM policies: {e}")
        sys.exit(1)

    print_success(f"Role has {len(current_actions)} allowed actions")

    # 3. Compute unused
    unused_actions = compute_unused(current_actions, used_actions)
    print_info(f"{len(unused_actions)} unused permissions identified")

    if not unused_actions:
        print_success("No unused permissions found — this role looks well-scoped already.")
        sys.exit(0)

    # 4. Claude analysis
    print_info("Asking Claude to assess removal safety...")
    try:
        api_key = get_anthropic_api_key(cfg)
        ai = anthropic.Anthropic(api_key=api_key)
        from .agent.analyst import analyze_aws_permissions
        findings = analyze_aws_permissions(
            ai, role_arn, current_actions, list(used_actions), unused_actions, days
        )
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Claude analysis failed: {e}")
        sys.exit(1)

    print_permission_table(findings)

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
        sys.exit(0)

    if mode.file_path:
        try:
            write_policy_file(mode.file_path, new_policy_json)
            print_output_written(mode.file_path)
        except OSError as e:
            print_error(f"Failed to write policy file: {e}")
            sys.exit(1)

    if mode.github:
        role_short = role_arn.split("/")[-1]
        try:
            from .shared.pr import open_pr
            pr_url = open_pr(
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
        except RuntimeError as e:
            print_error(str(e))
            sys.exit(1)

        if pr_url:
            print_success(f"PR opened: {pr_url}")
        else:
            print_warning("A PR for this role already exists.")


# ---------------------------------------------------------------------------
# scan gcp
# ---------------------------------------------------------------------------

@scan.command("gcp")
@click.option("--service-account", "service_account", required=True,
              help="Service account email")
@click.option("--project", required=True, help="GCP project ID")
@click.option("--days", default=90, show_default=True)
@click.option("--dry-run", is_flag=True, default=False,
              help="Print findings to terminal only (default behaviour if no output flag given)")
@click.option("--output", "output_path", default=None, metavar="PATH",
              help="Write recommended policy JSON to this file")
@click.option("--github", "open_github_pr", is_flag=True, default=False,
              help="Open a GitHub PR (requires token + repo in config)")
def scan_gcp(service_account, project, days, dry_run, output_path, open_github_pr):
    """Scan a GCP service account and output a least-privilege policy.

    Default (no flags): prints findings to terminal. Safe, no side effects.
    """
    cfg = load_config()
    mode = resolve_output_mode(dry_run, output_path, open_github_pr)

    # Validate GitHub config upfront — fail fast before expensive API calls
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

    if mode.is_dry_run:
        print_dry_run_notice()

    print_header(f"iam-zero GCP scan: {service_account}")

    # 1. Fetch audit logs
    print_info(f"Fetching Cloud Audit Logs for the last {days} days...")
    try:
        from .gcp.audit_logs import fetch_used_methods
        used_methods = fetch_used_methods(service_account, project, days)
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching audit logs: {e}")
        sys.exit(1)

    print_success(f"Found {len(used_methods)} unique API methods in audit logs")

    # 2. Fetch current IAM bindings
    print_info("Fetching current IAM role bindings...")
    try:
        from .gcp.iam_analyzer import get_service_account_roles, compute_unused_roles
        current_roles = get_service_account_roles(service_account, project)
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error fetching IAM bindings: {e}")
        sys.exit(1)

    print_success(f"Service account has {len(current_roles)} role bindings")

    unused_roles = compute_unused_roles(current_roles, used_methods)
    print_info(f"{len(unused_roles)} roles with no observed usage")

    if not unused_roles:
        print_success("No unused roles found — this service account looks well-scoped.")
        sys.exit(0)

    # 3. Claude analysis
    print_info("Asking Claude to assess removal safety...")
    try:
        api_key = get_anthropic_api_key(cfg)
        ai = anthropic.Anthropic(api_key=api_key)
        from .agent.analyst import analyze_gcp_permissions
        findings = analyze_gcp_permissions(
            ai, service_account, current_roles, list(used_methods), unused_roles, days
        )
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Claude analysis failed: {e}")
        sys.exit(1)

    print_permission_table(findings)

    # 4. Generate bindings
    from .gcp.policy_generator import generate_minimal_bindings
    current_bindings_json = json.dumps(
        {"serviceAccount": service_account, "currentRoles": current_roles}, indent=2
    )
    new_bindings_json = generate_minimal_bindings(service_account, current_roles, findings)

    # 5. Output
    if mode.is_dry_run:
        print_policy_terminal(current_bindings_json, new_bindings_json)
        sys.exit(0)

    if mode.file_path:
        try:
            write_policy_file(mode.file_path, new_bindings_json)
            print_output_written(mode.file_path)
        except OSError as e:
            print_error(f"Failed to write policy file: {e}")
            sys.exit(1)

    if mode.github:
        sa_short = service_account.split("@")[0]
        try:
            from .shared.pr import open_pr
            pr_url = open_pr(
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
        except RuntimeError as e:
            print_error(str(e))
            sys.exit(1)

        if pr_url:
            print_success(f"PR opened: {pr_url}")
        else:
            print_warning("A PR for this service account already exists.")
