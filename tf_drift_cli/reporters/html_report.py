from __future__ import annotations

from typing import Any

from ..models.resource import (
    DriftReport, DriftResult, DriftItem, DriftType, RiskLevel,
)


RISK_COLORS_CSS = {
    RiskLevel.HIGH: "#dc2626",
    RiskLevel.MEDIUM: "#d97706",
    RiskLevel.LOW: "#16a34a",
}

DRIFT_TYPE_LABELS = {
    DriftType.ATTRIBUTE_CHANGED: "Attribute Changed",
    DriftType.ATTRIBUTE_MISSING: "Attribute Missing",
    DriftType.EXTRA_ATTRIBUTE: "Extra Attribute",
    DriftType.RESOURCE_MISSING: "Resource Missing",
    DriftType.ORPHAN_RESOURCE: "Orphan Resource",
    DriftType.TYPE_MISMATCH: "Type Mismatch",
}


def format_html(report: DriftReport) -> str:
    parts: list[str] = []

    parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terraform Drift Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8fafc; color: #1e293b; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
.summary-card { background: white; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }
.summary-card .value { font-size: 24px; font-weight: 700; }
.summary-card .label { font-size: 12px; color: #64748b; text-transform: uppercase; }
.resource-section { margin: 16px 0; }
.details-panel { background: white; border-radius: 8px; margin: 8px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }
.details-header { padding: 12px 16px; cursor: pointer; display: flex; align-items: center; gap: 8px; }
.details-header:hover { background: #f1f5f9; }
.details-content { padding: 0 16px 16px; display: none; }
.details-content.open { display: block; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: white; }
.risk-high { background: #dc2626; }
.risk-medium { background: #d97706; }
.risk-low { background: #16a34a; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 14px; }
th { background: #f1f5f9; text-align: left; padding: 8px 12px; border-bottom: 2px solid #e2e8f0; }
td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }
code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
.remediation { background: #f0fdf4; border-left: 3px solid #16a34a; padding: 12px; margin: 8px 0; border-radius: 0 4px 4px 0; }
.remediation code { background: #dcfce7; }
.impact { background: #fffbeb; border-left: 3px solid #d97706; padding: 12px; margin: 8px 0; border-radius: 0 4px 4px 0; }
.env-diff-highlight { background: #fef2f2; font-weight: 600; }
.prod-unique { color: #dc2626; font-weight: 700; }
.arrow { transition: transform 0.2s; display: inline-block; }
.arrow.open { transform: rotate(90deg); }
</style>
</head>
<body>
<div class="container">
""")

    parts.append(f"<h1>Terraform Drift Detection Report</h1>")
    parts.append(f"<p><small>Generated: {report.timestamp} | State: <code>{report.state_file}</code> | Config: <code>{report.config_dir}</code>")
    if report.workspace:
        parts.append(f" | Workspace: {report.workspace}")
    parts.append("</small></p>")

    parts.append('<div class="summary">')
    parts.append(f'<div class="summary-card"><div class="value">{report.total_drifts}</div><div class="label">Total Drifts</div></div>')
    parts.append(f'<div class="summary-card"><div class="value" style="color:#dc2626">{report.high_risk_count}</div><div class="label">High Risk</div></div>')
    parts.append(f'<div class="summary-card"><div class="value" style="color:#d97706">{report.medium_risk_count}</div><div class="label">Medium Risk</div></div>')
    parts.append(f'<div class="summary-card"><div class="value" style="color:#16a34a">{report.low_risk_count}</div><div class="label">Low Risk</div></div>')
    parts.append(f'<div class="summary-card"><div class="value">{report.total_resources_in_state}</div><div class="label">State Resources</div></div>')
    parts.append(f'<div class="summary-card"><div class="value">{report.total_resources_in_config}</div><div class="label">Config Resources</div></div>')
    parts.append("</div>")

    if not report.results:
        parts.append('<div style="text-align:center;padding:40px;background:white;border-radius:8px;">')
        parts.append('<h2 style="color:#16a34a">✅ No Drift Detected!</h2>')
        parts.append('</div>')
    else:
        sorted_results = sorted(report.results, key=lambda r: {
            RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2,
        }.get(r.max_risk, 3))

        for i, result in enumerate(sorted_results):
            risk_css = f"risk-{result.max_risk.value}"
            parts.append('<div class="details-panel">')
            parts.append(f'<div class="details-header" onclick="togglePanel(\'panel-{i}\')">')
            parts.append(f'<span class="arrow" id="arrow-{i}">▶</span>')
            parts.append(f'<span class="badge {risk_css}">{result.max_risk.value.upper()}</span>')
            parts.append(f'<code>{result.resource_address}</code>')
            parts.append(f'<span style="color:#64748b">({len(result.drifts)} drifts)</span>')
            parts.append('</div>')

            parts.append(f'<div class="details-content" id="panel-{i}">')

            parts.append('<table><tr><th>Type</th><th>Attribute</th><th>Config</th><th>State</th><th>Risk</th></tr>')
            sorted_drifts = sorted(result.drifts, key=lambda d: d.severity_order())
            for drift in sorted_drifts:
                dtype = DRIFT_TYPE_LABELS.get(drift.drift_type, drift.drift_type.value)
                risk_d = f"risk-{drift.risk_level.value}"
                cv = _esc_html(drift.config_value)
                sv = _esc_html(drift.state_value)
                parts.append(f'<tr><td>{dtype}</td><td><code>{drift.attribute_path}</code></td><td>{cv}</td><td>{sv}</td><td><span class="badge {risk_d}">{drift.risk_level.value}</span></td></tr>')
            parts.append('</table>')

            if result.remediations:
                for rem in result.remediations:
                    rec = rem.get("recommended", {})
                    if rec:
                        desc = rec.get("description", "")
                        cmd = rec.get("command", "")
                        parts.append('<div class="remediation">')
                        parts.append(f'<strong>Remediation:</strong> {_esc_html(desc)}')
                        if cmd and not cmd.startswith("#"):
                            parts.append(f'<br><code>{_esc_html(cmd)}</code>')
                        parts.append('</div>')

            if result.impacted_resources:
                parts.append('<div class="impact">')
                parts.append('<strong>⚡ Impact Analysis:</strong><ul>')
                for imp in result.impacted_resources:
                    path_str = " → ".join(imp.propagation_path)
                    parts.append(f'<li>L{imp.level}: <code>{imp.resource_address}</code> (via {path_str})</li>')
                parts.append('</ul></div>')

            parts.append('</div></div>')

    if report.environment_diffs:
        parts.append('<h2>Environment Comparison</h2>')
        for diff in report.environment_diffs:
            res = diff.get("resource", "")
            attr = diff.get("attribute", "")
            is_prod = diff.get("is_production_unique", False)
            values = diff.get("values", {})
            parts.append(f'<div class="details-panel"><div class="details-header">')
            parts.append(f'<code>{res}.{attr}</code>')
            if is_prod:
                parts.append(' <span class="prod-unique">⚠ PRODUCTION UNIQUE</span>')
            parts.append('</div><div class="details-content"><table><tr>')
            for env in values:
                parts.append(f'<th>{env}</th>')
            parts.append('</tr><tr>')
            for env, val in values.items():
                parts.append(f'<td>{_esc_html(val)}</td>')
            parts.append('</tr></table></div></div>')

    parts.append("""
<script>
function togglePanel(id) {
  const panel = document.getElementById(id);
  const arrow = document.getElementById('arrow-' + id.split('-')[1]);
  panel.classList.toggle('open');
  arrow.classList.toggle('open');
}
</script>
</div>
</body>
</html>""")

    return "\n".join(parts)


def _esc_html(val: Any) -> str:
    if val is None:
        return "null"
    s = str(val)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    if len(s) > 80:
        s = s[:77] + "..."
    return s
