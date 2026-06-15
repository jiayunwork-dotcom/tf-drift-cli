package reporters

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
)

var riskEmoji = map[models.RiskLevel]string{
	models.RiskHigh:   "🔴",
	models.RiskMedium: "🟡",
	models.RiskLow:    "🟢",
}

var driftTypeLabel = map[models.DriftType]string{
	models.DriftAttributeChanged: "Attribute Changed",
	models.DriftAttributeMissing: "Attribute Missing",
	models.DriftExtraAttribute:   "Extra Attribute",
	models.DriftResourceMissing:  "Resource Missing",
	models.DriftOrphanResource:   "Orphan Resource",
	models.DriftTypeMismatch:     "Type Mismatch",
}

func FormatMarkdown(report *models.DriftReport) string {
	var sb strings.Builder

	sb.WriteString("# Terraform Drift Detection Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n", report.Timestamp))
	sb.WriteString(fmt.Sprintf("**State File:** `%s`\n", report.StateFile))
	sb.WriteString(fmt.Sprintf("**Config Dir:** `%s`\n", report.ConfigDir))
	if report.Workspace != "" {
		sb.WriteString(fmt.Sprintf("**Workspace:** %s\n", report.Workspace))
	}
	sb.WriteString("\n")

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	fmt.Fprintf(&sb, "| State Resources | %d |\n", report.TotalResourcesInState)
	fmt.Fprintf(&sb, "| Config Resources | %d |\n", report.TotalResourcesInConfig)
	fmt.Fprintf(&sb, "| Total Drifts | %d |\n", report.TotalDrifts)
	fmt.Fprintf(&sb, "| High Risk | %d |\n", report.HighRiskCount)
	fmt.Fprintf(&sb, "| Medium Risk | %d |\n", report.MediumRiskCount)
	fmt.Fprintf(&sb, "| Low Risk | %d |\n", report.LowRiskCount)
	if report.IgnoredCount > 0 {
		fmt.Fprintf(&sb, "| Ignored | %d |\n", report.IgnoredCount)
	}
	sb.WriteString("\n")

	if len(report.Results) == 0 {
		sb.WriteString("> ✅ **No drift detected!**\n\n")
		return sb.String()
	}

	sb.WriteString("## Drift Details\n\n")

	for _, result := range report.Results {
		riskIcon := riskEmoji[result.MaxRisk]
		fmt.Fprintf(&sb, "### %s `%s` — **%s** RISK\n\n",
			riskIcon, result.ResourceAddr, strings.ToUpper(string(result.MaxRisk)))

		sb.WriteString("| Type | Attribute | Config Value | State Value | Risk |\n")
		sb.WriteString("|------|-----------|-------------|-------------|------|\n")

		sort.Slice(result.Drifts, func(i, j int) bool {
			return result.Drifts[i].DriftType.SeverityOrder() < result.Drifts[j].DriftType.SeverityOrder()
		})

		for _, drift := range result.Drifts {
			dtype := driftTypeLabel[drift.DriftType]
			riskIconD := riskEmoji[drift.RiskLevel]
			cv := fmtValueMD(drift.ConfigValue)
			sv := fmtValueMD(drift.StateValue)
			fmt.Fprintf(&sb, "| %s | `%s` | %s | %s | %s %s |\n",
				dtype, drift.AttributePath, cv, sv, riskIconD, drift.RiskLevel)
		}
		sb.WriteString("\n")

		if len(result.Remediations) > 0 {
			sb.WriteString("**Remediation:**\n\n")
			for _, rem := range result.Remediations {
				if rem.Recommended != nil {
					desc := rem.Recommended.Description
					cmd := rem.Recommended.Command
					fmt.Fprintf(&sb, "- %s\n", desc)
					if cmd != "" && !strings.HasPrefix(cmd, "#") {
						sb.WriteString("  ```bash\n")
						fmt.Fprintf(&sb, "  %s\n", cmd)
						sb.WriteString("  ```\n")
					}
				}
			}
			sb.WriteString("\n")
		}

		if len(result.ImpactedResources) > 0 {
			sb.WriteString("**Impact Analysis:**\n\n")
			for _, imp := range result.ImpactedResources {
				pathStr := strings.Join(imp.PropagationPath, " → ")
				fmt.Fprintf(&sb, "- L%d: `%s` (via %s)\n",
					imp.Level, imp.ResourceAddr, pathStr)
			}
			sb.WriteString("\n")
		}
	}

	if len(report.EnvironmentDiffs) > 0 {
		sb.WriteString("## Environment Comparison\n\n")
		for _, diff := range report.EnvironmentDiffs {
			res := diff["resource"].(string)
			attr := diff["attribute"].(string)
			isProd, _ := diff["is_production_unique"].(bool)
			values := diff["values"].(map[string]interface{})

			envNames := make([]string, 0, len(values))
			for env := range values {
				envNames = append(envNames, env)
			}
			sort.Strings(envNames)

			parts := make([]string, 0, len(values))
			for _, env := range envNames {
				parts = append(parts, fmt.Sprintf("%s=%s", env, fmtValueMD(values[env])))
			}

			line := fmt.Sprintf("- `%s.%s`: %s", res, attr, strings.Join(parts, " | "))
			if isProd {
				line += " ⚠️ **PRODUCTION UNIQUE**"
			}
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func fmtValueMD(v interface{}) string {
	s := models.SerializeValue(v)
	s = strings.ReplaceAll(s, "|", "\\|")
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}

func FormatHTML(report *models.DriftReport) string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terraform Drift Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f8fafc; color: #1e293b; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
.summary-card { background: white; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }
.summary-card .value { font-size: 24px; font-weight: 700; }
.summary-card .label { font-size: 12px; color: #64748b; text-transform: uppercase; }
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
.prod-unique { color: #dc2626; font-weight: 700; }
.arrow { transition: transform 0.2s; display: inline-block; }
.arrow.open { transform: rotate(90deg); }
</style>
</head>
<body>
<div class="container">
`)

	sb.WriteString("<h1>Terraform Drift Detection Report</h1>")

	sb.WriteString(fmt.Sprintf("<p><small>Generated: %s | State: <code>%s</code> | Config: <code>%s</code>",
		report.Timestamp, report.StateFile, report.ConfigDir))

	if report.Workspace != "" {
		sb.WriteString(fmt.Sprintf(" | Workspace: %s", report.Workspace))
	}
	sb.WriteString("</small></p>")

	sb.WriteString(`<div class="summary">`)
	fmt.Fprintf(&sb, `<div class="summary-card"><div class="value">%d</div><div class="label">Total Drifts</div></div>`, report.TotalDrifts)
	fmt.Fprintf(&sb, `<div class="summary-card"><div class="value" style="color:#dc2626">%d</div><div class="label">High Risk</div></div>`, report.HighRiskCount)
	fmt.Fprintf(&sb, `<div class="summary-card"><div class="value" style="color:#d97706">%d</div><div class="label">Medium Risk</div></div>`, report.MediumRiskCount)
	fmt.Fprintf(&sb, `<div class="summary-card"><div class="value" style="color:#16a34a">%d</div><div class="label">Low Risk</div></div>`, report.LowRiskCount)
	fmt.Fprintf(&sb, `<div class="summary-card"><div class="value">%d</div><div class="label">State Resources</div></div>`, report.TotalResourcesInState)
	fmt.Fprintf(&sb, `<div class="summary-card"><div class="value">%d</div><div class="label">Config Resources</div></div>`, report.TotalResourcesInConfig)
	sb.WriteString("</div>")

	if len(report.Results) == 0 {
		sb.WriteString(`<div style="text-align:center;padding:40px;background:white;border-radius:8px;">`)
		sb.WriteString(`<h2 style="color:#16a34a">✅ No Drift Detected!</h2>
</div>`)
	} else {
		for i, result := range report.Results {
			riskClass := fmt.Sprintf("risk-%s", result.MaxRisk)
			sb.WriteString(`<div class="details-panel">`)
			sb.WriteString(fmt.Sprintf(`<div class="details-header" onclick="togglePanel('panel-%d')">`, i))
			sb.WriteString(fmt.Sprintf(`<span class="arrow" id="arrow-%d">▶</span>`, i))
			sb.WriteString(fmt.Sprintf(`<span class="badge %s">%s</span>`, riskClass, strings.ToUpper(string(result.MaxRisk))))
			sb.WriteString(fmt.Sprintf(`<code>%s</code>`, result.ResourceAddr))
			sb.WriteString(fmt.Sprintf(`<span style="color:#64748b">(%d drifts)</span>`, len(result.Drifts)))
			sb.WriteString(`</div>`)

			sb.WriteString(fmt.Sprintf(`<div class="details-content" id="panel-%d">`, i))

			sb.WriteString(`<table><tr><th>Type</th><th>Attribute</th><th>Config</th><th>State</th><th>Risk</th></tr>`)

			sort.Slice(result.Drifts, func(i, j int) bool {
				return result.Drifts[i].DriftType.SeverityOrder() < result.Drifts[j].DriftType.SeverityOrder()
			})

			for _, drift := range result.Drifts {
				dtype := driftTypeLabel[drift.DriftType]
				riskD := fmt.Sprintf("risk-%s", drift.RiskLevel)
				cv := escapeHTML(models.SerializeValue(drift.ConfigValue))
				sv := escapeHTML(models.SerializeValue(drift.StateValue))

				sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td></tr>`,
					dtype, drift.AttributePath, cv, sv, riskD, drift.RiskLevel))
			}

			sb.WriteString(`</table>`)

			if len(result.Remediations) > 0 {
				for _, rem := range result.Remediations {
					if rem.Recommended != nil {
						desc := rem.Recommended.Description
						cmd := rem.Recommended.Command
						sb.WriteString(`<div class="remediation">`)
						sb.WriteString(fmt.Sprintf(`<strong>Remediation:</strong> %s`, escapeHTML(desc)))
						if cmd != "" && !strings.HasPrefix(cmd, "#") {
							sb.WriteString(fmt.Sprintf(`<br><code>%s</code>`, escapeHTML(cmd)))
						}
						sb.WriteString(`</div>`)
					}
				}
			}

			if len(result.ImpactedResources) > 0 {
				sb.WriteString(`<div class="impact">`)
				sb.WriteString(`<strong>⚡ Impact Analysis:</strong><ul>`)
				for _, imp := range result.ImpactedResources {
					pathStr := strings.Join(imp.PropagationPath, " → ")
					sb.WriteString(fmt.Sprintf(`<li>L%d: <code>%s</code> (via %s)</li>`,
						imp.Level, imp.ResourceAddr, pathStr))
				}
				sb.WriteString(`</ul></div>`)
			}

			sb.WriteString(`</div></div>`)
		}
	}

	if len(report.EnvironmentDiffs) > 0 {
		sb.WriteString(`<h2>Environment Comparison</h2>`)
		for _, diff := range report.EnvironmentDiffs {
			res := diff["resource"].(string)
			attr := diff["attribute"].(string)
			isProd, _ := diff["is_production_unique"].(bool)
			values := diff["values"].(map[string]interface{})

			sb.WriteString(`<div class="details-panel"><div class="details-header">`)
			sb.WriteString(fmt.Sprintf(`<code>%s.%s</code>`, res, attr))
			if isProd {
				sb.WriteString(` <span class="prod-unique">⚠ PRODUCTION UNIQUE</span>`)
			}
			sb.WriteString(`</div><div class="details-content"><table><tr>`)

			envNames := make([]string, 0, len(values))
			for env := range values {
				envNames = append(envNames, env)
			}
			sort.Strings(envNames)

			for _, env := range envNames {
				sb.WriteString(fmt.Sprintf(`<th>%s</th>`, env))
			}

			sb.WriteString(`</tr><tr>`)

			for _, env := range envNames {
				sb.WriteString(fmt.Sprintf(`<td>%s</td>`, escapeHTML(models.SerializeValue(values[env]))))
			}

			sb.WriteString(`</tr></table></div></div>`)
		}
	}

	sb.WriteString(`
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
</html>`)

	return sb.String()
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}
