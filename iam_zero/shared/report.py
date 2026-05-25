from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Generator

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner(
    provider: str,
    identity: str,
    days: int,
    mode: str,
    project: str | None = None,
) -> None:
    title = Text()
    title.append("  iam-zero ⚡  ", style="bold cyan")
    title.append("IAM Least-Privilege Scanner", style="bold white")
    console.print(Panel(title, box=box.ROUNDED, padding=(0, 1)))
    console.print()

    rows: list[tuple[str, str]] = [("Provider", provider), ("Identity", identity)]
    if project:
        rows.append(("Project", project))
    rows.extend([("Lookback", f"{days} days"), ("Mode", mode)])

    for label, value in rows:
        console.print(f"  [dim]{label:<12}[/dim]{value}")
    console.print()


# ---------------------------------------------------------------------------
# Progress steps
# ---------------------------------------------------------------------------

@contextmanager
def scan_step(label: str) -> Generator[Callable[[str], None], None, None]:
    """Show a spinner while the block runs, then print ✓ with optional detail on exit."""
    detail_holder: list[str] = [""]

    def set_detail(d: str) -> None:
        detail_holder[0] = d

    with console.status(f"  [yellow]⣾[/yellow]  {label}...", spinner="dots"):
        yield set_detail

    suffix = f"  [dim]{detail_holder[0]}[/dim]" if detail_holder[0] else ""
    console.print(f"  [green]✓[/green]  {label}{suffix}")


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------

def _rec_cell(rec: str, risk: str) -> tuple[str, str]:
    """(display_text, style) for the Recommendation column."""
    r, ri = rec.lower(), risk.lower()
    if r == "remove":
        return "✂  Remove", "green"
    if r == "investigate":
        return "⚠  Review first", "yellow"
    if r == "keep":
        return ("✋ Keep (risky)", "red") if ri == "high" else ("✓  Keep", "dim")
    if r == "active":
        return "✓  Keep (active)", "dim"
    return rec, "white"


def _risk_cell(risk: str) -> tuple[str, str]:
    """(display_text, style) for the Risk column."""
    r = risk.upper()
    if r == "HIGH":
        return "HIGH", "bold red"
    if r in ("MED", "MEDIUM"):
        return "MED", "yellow"
    if r == "LOW":
        return "LOW", "green"
    return "—", "dim"


def print_findings_table(
    findings: list[dict],
    active_items: list[str],
    item_label: str = "Permission",
) -> None:
    """
    findings    — Claude's analysis of unused items (each has permission/recommendation/risk)
    active_items — items confirmed as actively used (shown as Keep active)
    item_label  — column header text ("Permission" for AWS, "Role" for GCP)
    """
    total = len(findings) + len(active_items)
    removable = sum(1 for f in findings if f.get("recommendation", "").lower() == "remove")

    summary = (
        f"  [bold]{total}[/bold] {item_label.lower()}s found  "
        f"[dim]│[/dim]  [bold]{len(active_items)}[/bold] used  "
        f"[dim]│[/dim]  [bold]{len(findings)}[/bold] unused  "
        f"[dim]│[/dim]  [bold green]{removable}[/bold green] removable"
    )
    console.print(Panel(Text.from_markup(summary), title="Findings", box=box.ROUNDED))
    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        show_edge=False,
    )
    table.add_column(item_label, min_width=34, no_wrap=False)
    table.add_column("Last Seen", min_width=10)
    table.add_column("Risk", min_width=6)
    table.add_column("Recommendation", min_width=18)

    for f in findings:
        risk_text, risk_style = _risk_cell(f.get("risk", ""))
        rec_text, rec_style = _rec_cell(f.get("recommendation", "investigate"), f.get("risk", ""))
        table.add_row(
            f.get("permission", ""),
            f"[dim]{f.get('last_used', 'Never')}[/dim]",
            f"[{risk_style}]{risk_text}[/{risk_style}]",
            f"[{rec_style}]{rec_text}[/{rec_style}]",
        )

    for item in active_items:
        table.add_row(
            f"[dim]{item}[/dim]",
            "[dim]In use[/dim]",
            "[dim]—[/dim]",
            "[dim]✓  Keep (active)[/dim]",
        )

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Summary panel + next steps
# ---------------------------------------------------------------------------

def _blast_radius(findings: list[dict], total: int) -> int:
    """Percentage of total permissions that are safe to remove."""
    if total == 0:
        return 0
    removable = sum(1 for f in findings if f.get("recommendation", "").lower() == "remove")
    return round(removable / total * 100)


def _next_steps(
    cloud: str,
    identity: str,
    project: str | None,
    is_dry_run: bool,
    has_file: bool,
    has_github: bool,
) -> list[tuple[str, str]]:
    """
    Returns (label, command) pairs for the Next steps block.
    Empty list means the user is done (github mode was used).
    """
    if has_github:
        return []

    if cloud == "gcp":
        proj_flag = f" --project {project}" if project else ""
        base = f"iam-zero scan gcp --service-account {identity}{proj_flag}"
    else:
        base = f"iam-zero scan aws --role {identity}"

    steps: list[tuple[str, str]] = []
    if is_dry_run or not has_file:
        steps.append(("Save policy    ", f"{base} --output policy.json"))
    steps.append(("Open GitHub PR ", f"{base} --github"))
    return steps


def print_summary_panel(
    findings: list[dict],
    active_items: list[str],
    cloud: str,
    identity: str,
    project: str | None,
    is_dry_run: bool,
    has_file: bool,
    has_github: bool,
) -> None:
    to_remove = sum(1 for f in findings if f.get("recommendation", "").lower() == "remove")
    to_review = sum(1 for f in findings if f.get("recommendation", "").lower() == "investigate")
    to_keep_risky = sum(1 for f in findings if f.get("recommendation", "").lower() == "keep")
    total = len(findings) + len(active_items)
    blast = _blast_radius(findings, total)

    lines: list[str] = []
    if to_remove:
        s = "s" if to_remove != 1 else ""
        lines.append(f"  [green]{to_remove}[/green] permission{s} safe to remove")
    if to_review:
        s = "s" if to_review != 1 else ""
        lines.append(f"  [yellow]{to_review}[/yellow] permission{s} flagged for manual review")
    if to_keep_risky:
        s = "s" if to_keep_risky != 1 else ""
        lines.append(f"  [red]{to_keep_risky}[/red] permission{s} kept — too risky to remove")
    if active_items:
        s = "s" if len(active_items) != 1 else ""
        lines.append(f"  [dim]{len(active_items)}[/dim] active — kept untouched")
    lines.append("")
    lines.append(f"  Blast radius reduction:  [bold cyan]{blast}%[/bold cyan]")

    console.print(Panel(Text.from_markup("\n".join(lines)), title="Summary", box=box.ROUNDED, padding=(1, 2)))

    steps = _next_steps(cloud, identity, project, is_dry_run, has_file, has_github)
    if steps:
        console.print("\n  [bold]Next steps:[/bold]")
        for label, cmd in steps:
            console.print(f"    [dim]{label}[/dim]  [cyan]{cmd}[/cyan]")
    console.print()


# ---------------------------------------------------------------------------
# File written / PR opened confirmations
# ---------------------------------------------------------------------------

def print_file_written(
    path: str,
    cloud: str,
    project: str | None = None,
    identity: str | None = None,
) -> None:
    console.print(f"\n  [green]✓[/green] Policy written to:  [bold]{path}[/bold]\n")
    console.print("  Review it, then apply:")
    if cloud == "gcp" and project:
        console.print(f"    [cyan]gcloud projects set-iam-policy {project} {path}[/cyan]")
    elif cloud == "aws" and identity:
        role_name = identity.split("/")[-1]
        console.print(
            f"    [cyan]aws iam put-role-policy --role-name {role_name} "
            f"--policy-name iam-zero-minimal --policy-document file://{path}[/cyan]"
        )
    else:
        console.print(f"    [cyan]# Apply {path} using your cloud CLI[/cyan]")
    console.print()


def print_pr_opened(pr_url: str, title: str, is_new: bool = True) -> None:
    verb = "opened" if is_new else "already open"
    console.print(f"\n  [green]✓[/green] GitHub PR {verb}:")
    console.print(f"    [dim]{title}[/dim]")
    console.print(f"    [cyan underline]{pr_url}[/cyan underline]")
    console.print()


# ---------------------------------------------------------------------------
# Error / status helpers
# ---------------------------------------------------------------------------

def print_error(msg: str) -> None:
    """Format a (possibly multi-line) error message with red ❌ prefix."""
    lines = msg.strip().split("\n")
    console.print(f"\n  [bold red]❌[/bold red]  [bold]{lines[0].strip()}[/bold]")
    for line in lines[1:]:
        stripped = line.strip()
        if stripped:
            console.print(f"     {stripped}")
    console.print()


def print_success(msg: str) -> None:
    console.print(f"  [green]✓[/green]  {msg}")


def print_warning(msg: str) -> None:
    console.print(f"  [yellow]⚠[/yellow]  {msg}")


def print_info(msg: str) -> None:
    console.print(f"  [dim]→[/dim]  {msg}")


def print_dry_run_notice() -> None:
    pass  # mode is shown in the banner; kept for any legacy callers


def print_policy_terminal(current_json: str, new_json: str) -> None:
    console.print("\n  [bold]Current policy[/bold]")
    console.print(current_json)
    console.print("\n  [bold]Proposed minimal policy[/bold]")
    console.print(new_json)
    console.print()


def print_output_written(path: str) -> None:
    """Backward-compat alias — prefer print_file_written for full apply instructions."""
    console.print(f"\n  [green]✓[/green] Policy written to:  [bold]{path}[/bold]")
