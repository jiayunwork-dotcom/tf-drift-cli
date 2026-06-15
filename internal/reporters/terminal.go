package reporters

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorMagenta = "\033[35m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

var riskColors = map[models.RiskLevel]string{
	models.RiskHigh:   colorRed,
	models.RiskMedium: colorYellow,
	models.RiskLow:    colorGreen,
}

var driftTypeLabels = map[models.DriftType]string{
	models.DriftAttributeChanged: "CHANGED",
	models.DriftAttributeMissing: "MISSING",
	models.DriftExtraAttribute:   "EXTRA",
	models.DriftResourceMissing:  "RESOURCE MISSING",
	models.DriftOrphanResource:   "ORPHAN",
	models.DriftTypeMismatch:     "TYPE MISMATCH",
}

var driftTypeColors = map[models.DriftType]string{
	models.DriftAttributeChanged: colorYellow,
	models.DriftAttributeMissing: colorCyan,
	models.DriftExtraAttribute:   colorBlue,
	models.DriftResourceMissing:  colorRed + colorBold,
	models.DriftOrphanResource:   colorMagenta,
	models.DriftTypeMismatch:     colorYellow,
}

func FormatTerminal(report *models.DriftReport) string {
	var sb strings.Builder

	printHeader(&sb, report)
	printSummary(&sb, report)

	if len(report.Results) == 0 {
		sb.WriteString("\n" + colorGreen + colorBold + "✓ No drift detected!" + colorReset + "\n\n")
		return sb.String()
	}

	fmt.Fprintf(&sb, "\n%sDrift Details%s (%d resources affected)\n\n",
		colorBold, colorReset, len(report.Results))

	for _, result := range report.Results {
		printResourceDrift(&sb, result)
	}

	if len(report.EnvironmentDiffs) > 0 {
		printEnvDiffs(&sb, report.EnvironmentDiffs)
	}

	return sb.String()
}

func printHeader(sb *strings.Builder, report *models.DriftReport) {
	sb.WriteString(colorBlue + "╭" + strings.Repeat("─", 118) + "╮" + colorReset + "\n")
	sb.WriteString(colorBlue + "│" + colorReset + " " + colorBold + "Terraform Drift Detection Report" + colorReset + "\n")
	sb.WriteString(colorBlue + "│" + colorReset + " " + colorDim + "Generated: " + report.Timestamp + colorReset + "\n")
	sb.WriteString(colorBlue + "│" + colorReset + " " + colorDim + "State: " + report.StateFile + colorReset + "\n")
	sb.WriteString(colorBlue + "│" + colorReset + " " + colorDim + "Config: " + report.ConfigDir + colorReset + "\n")
	if report.Workspace != "" {
		sb.WriteString(colorBlue + "│" + colorReset + " " + colorDim + "Workspace: " + report.Workspace + colorReset + "\n")
	}
	sb.WriteString(colorBlue + "╰" + strings.Repeat("─", 118) + "╯" + colorReset + "\n")
}

func printSummary(sb *strings.Builder, report *models.DriftReport) {
	fmt.Fprintf(sb, "\n%sSummary%s\n", colorBold, colorReset)
	sb.WriteString(strings.Repeat("─", 50) + "\n")
	fmt.Fprintf(sb, "%-25s %d\n", "State Resources:", report.TotalResourcesInState)
	fmt.Fprintf(sb, "%-25s %d\n", "Config Resources:", report.TotalResourcesInConfig)
	fmt.Fprintf(sb, "%-25s %d\n", "Total Drifts:", report.TotalDrifts)
	if report.TotalDrifts > 0 {
		fmt.Fprintf(sb, "%-25s %s%d%s high | %s%d%s medium | %s%d%s low\n",
			"Risk Breakdown:",
			colorRed, report.HighRiskCount, colorReset,
			colorYellow, report.MediumRiskCount, colorReset,
			colorGreen, report.LowRiskCount, colorReset)
	}
	if report.IgnoredCount > 0 {
		fmt.Fprintf(sb, "%-25s %d\n", "Ignored:", report.IgnoredCount)
	}
}

func printResourceDrift(sb *strings.Builder, result *models.DriftResult) {
	riskColor := riskColors[result.MaxRisk]
	resourceAddr := result.ResourceAddr

	sb.WriteString(fmt.Sprintf("\n%s●%s %s%s%s  %s[%s]%s\n",
		riskColor, colorReset,
		colorBold, resourceAddr, colorReset,
		riskColor, result.MaxRisk, colorReset))

	sort.Slice(result.Drifts, func(i, j int) bool {
		return result.Drifts[i].DriftType.SeverityOrder() < result.Drifts[j].DriftType.SeverityOrder()
	})

	for _, drift := range result.Drifts {
		driftColor := driftTypeColors[drift.DriftType]
		riskC := riskColors[drift.RiskLevel]
		label := driftTypeLabels[drift.DriftType]

		fmt.Fprintf(sb, "  %s%s%s  %s  %s[%s]%s\n",
			driftColor, label, colorReset,
			drift.AttributePath,
			riskC, drift.RiskLevel, colorReset)

		switch drift.DriftType {
		case models.DriftAttributeChanged:
			fmt.Fprintf(sb, "    Config: %s%s%s\n", colorCyan, fmtValue(drift.ConfigValue), colorReset)
			fmt.Fprintf(sb, "    State:  %s%s%s\n", colorYellow, fmtValue(drift.StateValue), colorReset)
		case models.DriftTypeMismatch:
			fmt.Fprintf(sb, "    Expected: %s%s%s = %s\n", colorCyan, drift.ExpectedType, colorReset, fmtValue(drift.ConfigValue))
			fmt.Fprintf(sb, "    Actual:   %s%s%s = %s\n", colorYellow, drift.ActualType, colorReset, fmtValue(drift.StateValue))
		case models.DriftAttributeMissing:
			fmt.Fprintf(sb, "    Config declares: %s%s%s\n", colorCyan, fmtValue(drift.ConfigValue), colorReset)
			fmt.Fprintf(sb, "    State: %snot present%s\n", colorDim, colorReset)
		case models.DriftExtraAttribute:
			fmt.Fprintf(sb, "    State value: %s%s%s\n", colorYellow, fmtValue(drift.StateValue), colorReset)
			fmt.Fprintf(sb, "    Config: %snot declared%s\n", colorDim, colorReset)
		}

		if result.Remediations != nil {
			for _, rem := range result.Remediations {
				if rem.Attribute == drift.AttributePath ||
					((drift.DriftType == models.DriftResourceMissing || drift.DriftType == models.DriftOrphanResource) && rem.Attribute == "*") {
					if rem.Recommended != nil {
						fmt.Fprintf(sb, "    %s💡 %s%s\n", colorDim, rem.Recommended.Description, colorReset)
						cmd := rem.Recommended.Command
						if cmd != "" && !strings.HasPrefix(cmd, "#") {
							fmt.Fprintf(sb, "      %s$ %s%s\n", colorBold, cmd, colorReset)
						}
					}
				}
			}
		}
	}

	if len(result.ImpactedResources) > 0 {
		fmt.Fprintf(sb, "  %s⚡ Impact Analysis%s\n", colorYellow+colorBold, colorReset)
		for _, imp := range result.ImpactedResources {
			pathStr := strings.Join(imp.PropagationPath, " → ")
			label := fmt.Sprintf("L%d: %s", imp.Level, imp.ResourceAddr)
			if imp.DriftAttribute != "" {
				label += fmt.Sprintf(" (via %s)", imp.DriftAttribute)
			}
			fmt.Fprintf(sb, "    %s%s%s  %s%s%s\n",
				colorYellow, label, colorReset,
				colorDim, pathStr, colorReset)
		}
	}
}

func printEnvDiffs(sb *strings.Builder, diffs []map[string]interface{}) {
	fmt.Fprintf(sb, "\n%sEnvironment Comparison%s\n\n", colorBold, colorReset)

	for _, diff := range diffs {
		res := diff["resource"].(string)
		attr := diff["attribute"].(string)
		isProdUnique, _ := diff["is_production_unique"].(bool)
		values := diff["values"].(map[string]interface{})

		line := fmt.Sprintf("  %s.%s: ", res, attr)
		parts := []string{}

		envNames := make([]string, 0, len(values))
		for env := range values {
			envNames = append(envNames, env)
		}
		sort.Strings(envNames)

		for _, env := range envNames {
			parts = append(parts, fmt.Sprintf("%s=%s", env, fmtValue(values[env])))
		}

		line += strings.Join(parts, " | ")

		if isProdUnique {
			line += "  " + colorRed + colorBold + "⚠ PRODUCTION UNIQUE" + colorReset
		}

		sb.WriteString(line + "\n")
	}
}

func fmtValue(v interface{}) string {
	s := models.SerializeValue(v)
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}
