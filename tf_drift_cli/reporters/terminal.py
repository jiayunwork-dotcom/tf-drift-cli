from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich.text import Text
from rich import box

from ..models.resource import (
    DriftReport, DriftResult, DriftItem, DriftType, RiskLevel,
)
from ..engine.impact import format_impact_tree


RISK_COLORS = {
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "green",
}

DRIFT_TYPE_LABELS = {
    DriftType.ATTRIBUTE_CHANGED: "CHANGED",
    DriftType.ATTRIBUTE_MISSING: "MISSING",
    DriftType.EXTRA_ATTRIBUTE: "EXTRA",
    DriftType.RESOURCE_MISSING: "RESOURCE MISSING",
    DriftType.ORPHAN_RESOURCE: "ORPHAN",
    DriftType.TYPE_MISMATCH: "TYPE MISMATCH",
}

DRIFT_TYPE_COLORS = {
    DriftType.ATTRIBUTE_CHANGED: "yellow",
    DriftType.ATTRIBUTE_MISSING: "cyan",
    DriftType.EXTRA_ATTRIBUTE: "blue",
    DriftType.RESOURCE_MISSING: "red bold",
    DriftType.ORPHAN_RESOURCE: "magenta",
    DriftType.TYPE_MISMATCH: "yellow",
}


def format_terminal(report: DriftReport) -> str:
    import io
    buf = io.StringIO()
    console = Console(file=buf, width=120, force_terminal=True)

    _print_header(console, report)
    _print_summary(console, report)

    if not report.results:
        console.print("\n[bold green]✓ No drift detected![/bold green]\n")
        return buf.getvalue()

    console.print(f"\n[bold]Drift Details[/bold] ({len(report.results)} resources affected)\n")

    sorted_results = sorted(report.results, key=lambda r: {
        RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2,
    }.get(r.max_risk, 3))

    for result in sorted_results:
        _print_resource_drift(console, result)

    if report.environment_diffs:
        _print_env_diffs(console, report.environment_diffs)

    return buf.getvalue()


def _print_header(console: Console, report: DriftReport):
    header = Text()
    header.append("Terraform Drift Detection Report", style="bold white")
    header.append("\n")
    header.append(f"Generated: {report.timestamp}", style="dim")
    header.append("\n")
    header.append(f"State: {report.state_file}", style="dim")
    header.append("  |  ", style="dim")
    header.append(f"Config: {report.config_dir}", style="dim")
    if report.workspace:
        header.append("  |  ", style="dim")
        header.append(f"Workspace: {report.workspace}", style="dim")
    console.print(Panel(header, border_style="blue"))


def _print_summary(console: Console, report: DriftReport):
    summary = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column()

    summary.add_row("State Resources:", str(report.total_resources_in_state))
    summary.add_row("Config Resources:", str(report.total_resources_in_config))
    summary.add_row("Total Drifts:", str(report.total_drifts))

    if report.total_drifts > 0:
        summary.add_row(
            "Risk Breakdown:",
            f"[red]{report.high_risk_count} high[/red] | [yellow]{report.medium_risk_count} medium[/yellow] | [green]{report.low_risk_count} low[/green]",
        )
    if report.ignored_count:
        summary.add_row("Ignored:", str(report.ignored_count))

    console.print(summary)


def _print_resource_drift(console: Console, result: DriftResult):
    risk_color = RISK_COLORS.get(result.max_risk, "white")

    tree = Tree(f"[{risk_color}]● {result.resource_address}[/{risk_color}]  [{risk_color}]{result.max_risk.value.upper()}[/{risk_color}]")

    sorted_drifts = sorted(result.drifts, key=lambda d: d.severity_order())

    for drift in sorted_drifts:
        drift_color = DRIFT_TYPE_COLORS.get(drift.drift_type, "white")
        risk_c = RISK_COLORS.get(drift.risk_level, "white")
        label = DRIFT_TYPE_LABELS.get(drift.drift_type, drift.drift_type.value)

        branch = tree.add(f"[{drift_color}]{label}[/{drift_color}]  {drift.attribute_path}  [{risk_c}][{drift.risk_level.value}][/{risk_c}]")

        if drift.drift_type == DriftType.ATTRIBUTE_CHANGED:
            branch.add(f"Config: [cyan]{_fmt_val(drift.config_value)}[/cyan]")
            branch.add(f"State:  [orange1]{_fmt_val(drift.state_value)}[/orange1]")
        elif drift.drift_type == DriftType.TYPE_MISMATCH:
            branch.add(f"Expected: [cyan]{drift.expected_type}[/cyan] = {_fmt_val(drift.config_value)}")
            branch.add(f"Actual:   [orange1]{drift.actual_type}[/orange1] = {_fmt_val(drift.state_value)}")
        elif drift.drift_type == DriftType.ATTRIBUTE_MISSING:
            branch.add(f"Config declares: [cyan]{_fmt_val(drift.config_value)}[/cyan]")
            branch.add(f"State: [dim]not present[/dim]")
        elif drift.drift_type == DriftType.EXTRA_ATTRIBUTE:
            branch.add(f"State value: [orange1]{_fmt_val(drift.state_value)}[/orange1]")
            branch.add(f"Config: [dim]not declared[/dim]")
        elif drift.drift_type in (DriftType.RESOURCE_MISSING, DriftType.ORPHAN_RESOURCE):
            pass

        if result.remediations:
            for rem in result.remediations:
                if rem.get("attribute") == drift.attribute_path or (drift.drift_type in (DriftType.RESOURCE_MISSING, DriftType.ORPHAN_RESOURCE) and rem.get("attribute") == "*"):
                    rec = rem.get("recommended", {})
                    if rec:
                        branch.add(f"💡 [dim]{rec.get('description', '')}[/dim]")
                        cmd = rec.get("command", "")
                        if cmd and not cmd.startswith("#"):
                            branch.add(f"  [bold]$ {cmd}[/bold]")

    if result.impacted_resources:
        impact_tree = tree.add("[bold yellow]⚡ Impact Analysis[/bold yellow]")
        impact_data = format_impact_tree(result)
        for item in impact_data:
            level = item["level"]
            path = item.get("propagation_path", "")
            attr = item.get("drift_attribute", "")
            label = f"L{level}: {item['resource']}"
            if attr:
                label += f" (via {attr})"
            impact_tree.add(f"[yellow]{label}[/yellow]")

    console.print(tree)
    console.print()


def _print_env_diffs(console: Console, env_diffs: list[dict[str, Any]]):
    console.print("\n[bold]Environment Comparison[/bold]\n")

    for diff in env_diffs:
        res = diff.get("resource", "")
        attr = diff.get("attribute", "")
        is_prod_unique = diff.get("is_production_unique", False)

        line = f"  {res}.{attr}: "
        values = diff.get("values", {})
        parts = []
        for env, val in values.items():
            parts.append(f"{env}={_fmt_val(val)}")
        line += " | ".join(parts)

        if is_prod_unique:
            line += "  [red bold]⚠ PRODUCTION UNIQUE[/red bold]"

        console.print(line)


def _fmt_val(val: Any, max_len: int = 50) -> str:
    if val is None:
        return "null"
    s = str(val)
    if len(s) > max_len:
        s = s[:max_len - 3] + "..."
    return s
