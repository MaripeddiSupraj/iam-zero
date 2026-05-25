from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_header(title: str) -> None:
    console.print(Panel(f"[bold cyan]{title}[/bold cyan]", box=box.ROUNDED))


def print_success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green] {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[bold yellow]⚠[/bold yellow] {msg}")


def print_error(msg: str) -> None:
    console.print(f"[bold red]✗[/bold red] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[dim]→[/dim] {msg}")


def print_permission_table(findings: list[dict]) -> None:
    """
    findings: list of {permission, last_used, recommendation, risk, reason}
    """
    table = Table(
        "Permission",
        "Last Used",
        "Recommendation",
        "Risk",
        "Reason",
        box=box.SIMPLE_HEAD,
        show_lines=False,
    )
    risk_colors = {"low": "green", "medium": "yellow", "high": "red", "unknown": "dim"}
    rec_colors = {"remove": "red", "keep": "green", "investigate": "yellow"}

    for f in findings:
        risk = f.get("risk", "unknown").lower()
        rec = f.get("recommendation", "investigate").lower()
        table.add_row(
            f["permission"],
            f.get("last_used", "never"),
            f"[{rec_colors.get(rec, 'white')}]{rec}[/]",
            f"[{risk_colors.get(risk, 'white')}]{risk}[/]",
            f.get("reason", ""),
        )
    console.print(table)


def print_dry_run_notice() -> None:
    console.print(
        Panel(
            "[bold yellow]DRY RUN[/bold yellow] — terminal output only. "
            "Use [bold]--output <path>[/bold] to save policy JSON or "
            "[bold]--github[/bold] to open a PR.",
            box=box.ROUNDED,
        )
    )


def print_policy_terminal(current_json: str, new_json: str) -> None:
    console.print("\n[bold]Current policy[/bold]")
    console.print(current_json)
    console.print("\n[bold]Proposed minimal policy[/bold]")
    console.print(new_json)


def print_output_written(path: str) -> None:
    print_success(f"Policy written to {path}")
