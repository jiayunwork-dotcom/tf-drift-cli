package reporters

import (
	"encoding/json"

	"github.com/tf-drift/tf-drift/internal/models"
)

func FormatJSON(report *models.DriftReport, opts *models.ReportOptions) (string, error) {
	data := reportToDict(report, opts)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func reportToDict(report *models.DriftReport, opts *models.ReportOptions) map[string]interface{} {
	results := make([]map[string]interface{}, len(report.Results))
	for i, r := range report.Results {
		results[i] = resultToDict(r)
	}

	base := map[string]interface{}{
		"metadata":        metadataToDict(report.Metadata),
		"timestamp":       report.Timestamp,
		"state_file":      report.StateFile,
		"config_dir":      report.ConfigDir,
		"workspace":       report.Workspace,
		"options": map[string]interface{}{
			"group_by": opts.GroupBy,
			"min_risk": string(opts.MinRisk),
			"sort":     opts.Sort,
		},
		"summary": map[string]interface{}{
			"total_resources_in_state":  report.TotalResourcesInState,
			"total_resources_in_config": report.TotalResourcesInConfig,
			"total_drifts":              report.TotalDrifts,
			"high_risk_count":           report.HighRiskCount,
			"medium_risk_count":         report.MediumRiskCount,
			"low_risk_count":            report.LowRiskCount,
			"ignored_count":             report.IgnoredCount,
		},
		"results":           results,
		"environment_diffs": report.EnvironmentDiffs,
	}

	groups := report.GroupResults(opts.GroupBy)
	if groups != nil {
		groupData := make([]map[string]interface{}, len(groups))
		for i, g := range groups {
			groupResults := make([]map[string]interface{}, len(g.Results))
			for j, r := range g.Results {
				groupResults[j] = resultToDict(r)
			}
			groupData[i] = map[string]interface{}{
				"group_name":   g.GroupName,
				"resource_cnt": g.ResourceCnt,
				"drift_cnt":    g.DriftCnt,
				"results":      groupResults,
			}
		}
		base["groups"] = groupData
	}

	return base
}

func metadataToDict(m *models.ReportMetadata) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"tool_version":   m.ToolVersion,
		"timestamp":      m.Timestamp,
		"command":        m.Command,
		"state_file_abs": m.StateFileAbs,
		"config_dir_abs": m.ConfigDirAbs,
		"go_version":     m.GoVersion,
	}
}

func resultToDict(result *models.DriftResult) map[string]interface{} {
	drifts := make([]map[string]interface{}, len(result.Drifts))
	for i, d := range result.Drifts {
		drifts[i] = driftToDict(d)
	}

	impacted := make([]map[string]interface{}, len(result.ImpactedResources))
	for i, imp := range result.ImpactedResources {
		impacted[i] = map[string]interface{}{
			"resource_address":  imp.ResourceAddr,
			"level":             imp.Level,
			"propagation_path":  imp.PropagationPath,
			"drift_attribute":   imp.DriftAttribute,
		}
	}

	return map[string]interface{}{
		"resource_address":     result.ResourceAddr,
		"resource_type":        result.ResourceType,
		"max_risk":             string(result.MaxRisk),
		"drifts":               drifts,
		"impacted_resources":   impacted,
		"remediations":         result.Remediations,
	}
}

func driftToDict(drift *models.DriftItem) map[string]interface{} {
	d := map[string]interface{}{
		"type":         string(drift.DriftType),
		"resource":     drift.ResourceAddr,
		"attribute":    drift.AttributePath,
		"config_value": serialize(drift.ConfigValue),
		"state_value":  serialize(drift.StateValue),
		"risk_level":   string(drift.RiskLevel),
	}
	if drift.DriftType == models.DriftTypeMismatch {
		d["expected_type"] = drift.ExpectedType
		d["actual_type"] = drift.ActualType
	}
	return d
}

func serialize(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch v.(type) {
	case map[string]interface{}, []interface{}, int, int64, float64, bool:
		return v
	default:
		return models.SerializeValue(v)
	}
}
