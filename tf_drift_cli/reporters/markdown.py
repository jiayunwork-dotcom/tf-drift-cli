from __future__ import annotations

from typing import Any

from ..models.resource import (
    DriftReport, DriftResult, DriftItem, DriftType, RiskLevel,
)


RISK_EMOJI = {
    RiskLevel.HIGH: "🔴",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.LOW: "🟢",
}

DRIFT_TYPE_LABEL = {
    DriftType.ATTRIBUTE_CHANGED: "Attribute Changed",
    DriftType.ATTRIBUTE_MISSING: "Attribute Missing",
    DriftType.EXTRA_ATTRIBUTE: "Extra Attribute",
    DriftType.RESOURCE_MISSING: "Resource Missing",
    DriftType.ORPHAN_RESOURCE: "Orphan Resource",
    DriftType.TYPE_MISMATCH: "Type Mismatch",
}


def format_markdown(report: DriftReport) -> str:
    lines: list[str] = []

    lines.append("# Terraform Drift Detection Report")
    lines.append("")
    lines.append(f"**Generated:** {report.timestamp}")
    lines.append(f"**State File:** `{report.state_file}`")
    lines.append(f"**Config Dir:** `{report.config_dir}`")
    if report.workspace:
        lines.append(f"**Workspace:** {report.workspace}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| State Resources | {report.total_resources_in_state} |")
    lines.append(f"| Config Resources | {report.total_resources_in_config} |")
    lines.append(f"| Total Drifts | {report.total_drifts} |")
    lines.append(f"| High Risk | {report.high_risk_count} |")
    lines.append(f"| Medium Risk | {report.medium_risk_count} |")
    lines.append(f"| Low Risk | {report.low_risk_count} |")
    if report.ignored_count:
        lines.append(f"| Ignored | {report.ignored_count} |")
    lines.append("")

    if not report.results:
        lines.append("> ✅ **No drift detected!**")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Drift Details")
    lines.append("")

    sorted_results = sorted(report.results, key=lambda r: {
        RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2,
    }.get(r.max_risk, 3))

    for result in sorted_results:
        risk_icon = RISK_EMOJI.get(result.max_risk, "")
        lines.append(f"### {risk_icon} `{result.resource_address}` — {result.max_risk.value.upper()} RISK")
        lines.append("")

        lines.append("| Type | Attribute | Config Value | State Value | Risk |")
        lines.append("|------|-----------|-------------|-------------|------|")

        sorted_drifts = sorted(result.drifts, key=lambda d: d.severity_order())
        for drift in sorted_drifts:
            dtype = DRIFT_TYPE_LABEL.get(drift.drift_type, drift.drift_type.value)
            risk_icon_d = RISK_EMOJI.get(drift.risk_level, "")
            cv = _fmt_md(drift.config_value)
            sv = _fmt_md(drift.state_value)
            lines.append(f"| {dtype} | `{drift.attribute_path}` | {cv} | {sv} | {risk_icon_d} {drift.risk_level.value} |")

        lines.append("")

        if result.remediations:
            lines.append("**Remediation:**")
            lines.append("")
            for rem in result.remediations:
                rec = rem.get("recommended", {})
                if rec:
                    desc = rec.get("description", "")
                    cmd = rec.get("command", "")
                    lines.append(f"- {desc}")
                    if cmd and not cmd.startswith("#"):
                        lines.append(f"  ```bash")
                        lines.append(f"  {cmd}")
                        lines.append(f"  ```")
            lines.append("")

        if result.impacted_resources:
            lines.append("**Impact Analysis:**")
            lines.append("")
            for imp in result.impacted_resources:
                path_str = " → ".join(imp.propagation_path)
                lines.append(f"- L{imp.level}: `{imp.resource_address}` (via {path_str})")
            lines.append("")

    if report.environment_diffs:
        lines.append("## Environment Comparison")
        lines.append("")
        for diff in report.environment_diffs:
            res = diff.get("resource", "")
            attr = diff.get("attribute", "")
            is_prod = diff.get("is_production_unique", False)
            values = diff.get("values", {})
            parts = [f"{env}={_fmt_md(val)}" for env, val in values.items()]
            line = f"- `{res}.{attr}`: {' | '.join(parts)}"
            if is_prod:
                line += " ⚠️ **PRODUCTION UNIQUE**"
            lines.append(line)
        lines.append("")

    return "\n".join(lines)


def _fmt_md(val: Any) -> str:
    if val is None:
        return "null"
    s = str(val)
    s = s.replace("|", "\\|")
    if len(s) > 60:
        s = s[:57] + "..."
    return s
