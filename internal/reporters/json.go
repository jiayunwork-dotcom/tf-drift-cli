package reporters

import (
	"encoding/json"

	"github.com/tf-drift/tf-drift/internal/models"
)

func FormatJSON(report *models.DriftReport) (string, error) {
	data := reportToDict(report)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func reportToDict(report *models.DriftReport) map[string]interface{} {
	results := make([]map[string]interface{}, len(report.Results))
	for i, r := range report.Results {
		results[i] = resultToDict(r)
	}

	return map[string]interface{}{
		"timestamp":   report.Timestamp,
		"state_file":  report.StateFile,
		"config_dir":  report.ConfigDir,
		"workspace":   report.Workspace,
		"summary": map[string]interface{}{
			"total_resources_in_state":  report.TotalResourcesInState,
			"total_resources_in_config": report.TotalResourcesInConfig,
			"total_drifts":              report.TotalDrifts,
			"high_risk_count":           report.HighRiskCount,
			"medium_risk_count":         report.MediumRiskCount,
			"low_risk_count":            report.LowRiskCount,
			"ignored_count":             report.IgnoredCount,
		},
		"results":            results,
		"environment_diffs":  report.EnvironmentDiffs,
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
