package engine

import (
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
)

func AnalyzeImpact(results []*models.DriftResult, depGraph *models.DependencyGraph) []*models.DriftResult {
	for _, result := range results {
		if len(result.Drifts) == 0 {
			continue
		}

		downstream := depGraph.GetDownstream(result.ResourceAddr)
		impacted := []*models.ImpactNode{}

		for _, nodes := range downstream {
			for _, node := range nodes {
				driftAttrs := []string{}
				for _, drift := range result.Drifts {
					if drift.DriftType == models.DriftAttributeChanged ||
						drift.DriftType == models.DriftAttributeMissing ||
						drift.DriftType == models.DriftTypeMismatch {
						driftAttrs = append(driftAttrs, drift.AttributePath)
					}
				}

				impacted = append(impacted, &models.ImpactNode{
					ResourceAddr:    node.ResourceAddr,
					Level:           node.Level,
					PropagationPath: node.PropagationPath,
					DriftAttribute:  strings.Join(driftAttrs, ", "),
				})
			}
		}

		result.ImpactedResources = impacted

		if len(impacted) > 0 && result.MaxRisk == models.RiskLow {
			for _, drift := range result.Drifts {
				if drift.RiskLevel == models.RiskLow {
					drift.RiskLevel = models.RiskMedium
				}
			}
			result.ComputeMaxRisk()
		}
	}

	return results
}

func FormatImpactTree(result *models.DriftResult) []map[string]interface{} {
	if len(result.ImpactedResources) == 0 {
		return nil
	}

	tree := []map[string]interface{}{}
	for _, node := range result.ImpactedResources {
		tree = append(tree, map[string]interface{}{
			"resource":          node.ResourceAddr,
			"level":             node.Level,
			"level_label":       "L" + models.ToString(node.Level) + " dependency",
			"propagation_path":  strings.Join(node.PropagationPath, " -> "),
			"drift_attribute":   node.DriftAttribute,
		})
	}

	return tree
}
