package remediation

import (
	"github.com/tf-drift/tf-drift/internal/models"
)

func GenerateRemediations(results []*models.DriftResult, stateResources map[string]*models.TfResource) []*models.DriftResult {
	for _, result := range results {
		result.Remediations = []*models.Remediation{}
		for _, drift := range result.Drifts {
			rem := remediateDrift(drift, result, stateResources)
			if rem != nil {
				result.Remediations = append(result.Remediations, rem)
			}
		}
	}
	return results
}

func remediateDrift(
	drift *models.DriftItem,
	result *models.DriftResult,
	stateResources map[string]*models.TfResource,
) *models.Remediation {
	switch drift.DriftType {
	case models.DriftAttributeChanged:
		return remediateAttributeChanged(drift, result)
	case models.DriftResourceMissing:
		return remediateResourceMissing(drift, result, stateResources)
	case models.DriftOrphanResource:
		return remediateOrphanResource(drift, result)
	case models.DriftAttributeMissing:
		return remediateAttributeMissing(drift, result)
	case models.DriftExtraAttribute:
		return remediateExtraAttribute(drift, result)
	case models.DriftTypeMismatch:
		return remediateTypeMismatch(drift, result)
	}
	return nil
}

func remediateAttributeChanged(drift *models.DriftItem, result *models.DriftResult) *models.Remediation {
	rebuildAttrs := map[string]bool{
		"instance_type": true, "ami": true, "image_id": true,
		"instance_class": true, "engine": true, "engine_version": true,
		"multi_az": true, "storage_type": true, "allocated_storage": true,
		"node_type": true, "cluster_type": true, "machine_type": true,
		"disk_size": true, "image": true, "size": true,
	}

	attrName := drift.AttributePath
	parts := splitAttr(attrName)
	last := parts[len(parts)-1]
	isRebuild := rebuildAttrs[last]

	applyRisk := "low"
	applyNote := "This will update the resource in-place"
	if isRebuild {
		applyRisk = "high"
		applyNote = "This will rebuild the resource"
	}

	options := []models.RemediationOption{
		{
			Action:      "terraform apply",
			Description: "Apply configuration to update actual state to match desired: " + drift.AttributePath,
			Command:     "terraform apply -target=" + drift.ResourceAddr,
			Risk:        applyRisk,
			Note:        applyNote,
		},
		{
			Action:      "update config",
			Description: "Modify configuration to match current actual state for " + drift.AttributePath,
			Command:     "# Edit config: set " + drift.AttributePath + " = " + formatValue(drift.StateValue),
			Risk:        "low",
			Note:        "Accept current state as desired state",
		},
	}

	recommended := &options[0]
	if drift.RiskLevel == models.RiskHigh {
		recommended = &options[1]
	}

	return &models.Remediation{
		DriftType:   string(drift.DriftType),
		Resource:    drift.ResourceAddr,
		Attribute:   drift.AttributePath,
		ConfigValue: models.SerializeValue(drift.ConfigValue),
		StateValue:  models.SerializeValue(drift.StateValue),
		Options:     options,
		Recommended: recommended,
		RiskLevel:   string(drift.RiskLevel),
	}
}

func remediateResourceMissing(
	drift *models.DriftItem,
	result *models.DriftResult,
	stateResources map[string]*models.TfResource,
) *models.Remediation {
	resourceAddr := drift.ResourceAddr
	parts := splitAttr(resourceAddr)
	resourceType := parts[0]
	resourceName := parts[1]
	resourceID := "<RESOURCE_ID>"

	if stateResources != nil {
		for _, res := range stateResources {
			if res.ResourceType == resourceType && res.ResourceName == resourceName {
				if res.ResourceID != "" {
					resourceID = res.ResourceID
					break
				}
			}
		}
	}

	options := []models.RemediationOption{
		{
			Action:      "terraform import",
			Description: "Import existing resource into Terraform state",
			Command:     "terraform import " + resourceAddr + " " + resourceID,
			Risk:        "medium",
			Note:        "Ensure the resource ID is correct before importing",
		},
		{
			Action:      "terraform apply",
			Description: "Create the resource as defined in configuration",
			Command:     "terraform apply -target=" + resourceAddr,
			Risk:        "high",
			Note:        "This will create a NEW resource (may duplicate existing infrastructure)",
		},
	}

	return &models.Remediation{
		DriftType:   string(drift.DriftType),
		Resource:    resourceAddr,
		Attribute:   "*",
		Options:     options,
		Recommended: &options[0],
		RiskLevel:   string(drift.RiskLevel),
	}
}

func remediateOrphanResource(drift *models.DriftItem, result *models.DriftResult) *models.Remediation {
	resourceAddr := drift.ResourceAddr

	options := []models.RemediationOption{
		{
			Action:      "terraform state rm",
			Description: "Remove orphan resource from state (resource no longer in config)",
			Command:     "terraform state rm " + resourceAddr,
			Risk:        "medium",
			Note:        "The actual cloud resource will NOT be destroyed",
		},
		{
			Action:      "restore config",
			Description: "Add the resource definition back to configuration files",
			Command:     "# Add resource block for " + resourceAddr + " to .tf files",
			Risk:        "low",
			Note:        "Accept the resource as managed infrastructure",
		},
	}

	return &models.Remediation{
		DriftType:   string(drift.DriftType),
		Resource:    resourceAddr,
		Attribute:   "*",
		Options:     options,
		Recommended: &options[0],
		RiskLevel:   string(drift.RiskLevel),
	}
}

func remediateAttributeMissing(drift *models.DriftItem, result *models.DriftResult) *models.Remediation {
	options := []models.RemediationOption{
		{
			Action:      "terraform apply",
			Description: "Apply to create attribute " + drift.AttributePath + " in actual state",
			Command:     "terraform apply -target=" + drift.ResourceAddr,
			Risk:        "medium",
			Note:        "New configuration attribute not yet applied",
		},
		{
			Action:      "remove from config",
			Description: "Remove the undeclared attribute from configuration",
			Command:     "# Remove " + drift.AttributePath + " from " + drift.ResourceAddr + " config",
			Risk:        "low",
			Note:        "Only if the attribute was added by mistake",
		},
	}

	return &models.Remediation{
		DriftType:   string(drift.DriftType),
		Resource:    drift.ResourceAddr,
		Attribute:   drift.AttributePath,
		ConfigValue: models.SerializeValue(drift.ConfigValue),
		Options:     options,
		Recommended: &options[0],
		RiskLevel:   string(drift.RiskLevel),
	}
}

func remediateExtraAttribute(drift *models.DriftItem, result *models.DriftResult) *models.Remediation {
	options := []models.RemediationOption{
		{
			Action:      "accept as default",
			Description: "Attribute " + drift.AttributePath + " is likely a provider default or computed value",
			Command:     "# No action needed - provider-set default",
			Risk:        "low",
			Note:        "Provider automatically fills this attribute",
		},
		{
			Action:      "add to config",
			Description: "Explicitly declare " + drift.AttributePath + " in configuration",
			Command:     "# Add " + drift.AttributePath + " = " + formatValue(drift.StateValue) + " to config",
			Risk:        "low",
			Note:        "Make the implicit explicit for tracking",
		},
	}

	return &models.Remediation{
		DriftType:   string(drift.DriftType),
		Resource:    drift.ResourceAddr,
		Attribute:   drift.AttributePath,
		StateValue:  models.SerializeValue(drift.StateValue),
		Options:     options,
		Recommended: &options[0],
		RiskLevel:   string(drift.RiskLevel),
	}
}

func remediateTypeMismatch(drift *models.DriftItem, result *models.DriftResult) *models.Remediation {
	options := []models.RemediationOption{
		{
			Action:      "terraform apply",
			Description: "Apply to reconcile type mismatch for " + drift.AttributePath,
			Command:     "terraform apply -target=" + drift.ResourceAddr,
			Risk:        "medium",
			Note:        "Expected " + drift.ExpectedType + ", got " + drift.ActualType,
		},
		{
			Action:      "fix config type",
			Description: "Update config value type to match state",
			Command:     "# Change " + drift.AttributePath + " to " + drift.ActualType + " type: " + formatValue(drift.StateValue),
			Risk:        "low",
			Note:        "Align configuration type with actual state",
		},
	}

	return &models.Remediation{
		DriftType:    string(drift.DriftType),
		Resource:     drift.ResourceAddr,
		Attribute:    drift.AttributePath,
		ExpectedType: drift.ExpectedType,
		ActualType:   drift.ActualType,
		Options:      options,
		Recommended:  &options[1],
		RiskLevel:    string(drift.RiskLevel),
	}
}

func splitAttr(s string) []string {
	parts := []string{}
	current := ""
	for _, ch := range s {
		if ch == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func formatValue(v interface{}) string {
	s := models.SerializeValue(v)
	if len(s) > 50 {
		return s[:47] + "..."
	}
	return s
}
