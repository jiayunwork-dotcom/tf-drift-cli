package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
	"github.com/tf-drift/tf-drift/internal/parsers/hcl"
	"github.com/tf-drift/tf-drift/internal/parsers/tfstate"
)

var (
	computedAttrs = map[string]bool{
		"id": true, "arn": true, "owner_id": true, "creation_date": true,
		"created_time": true, "last_modified": true, "etag": true,
		"unique_id": true, "dns_name": true, "fqdn": true, "zone_id": true,
		"vpc_id": true, "subnet_id": true, "endpoint": true,
		"connection_string": true,
	}

	rebuildTriggeringAttrs = map[string]bool{
		"instance_type": true, "ami": true, "image_id": true,
		"instance_class": true, "engine": true, "engine_version": true,
		"multi_az": true, "storage_type": true, "allocated_storage": true,
		"node_type": true, "cluster_type": true, "machine_type": true,
		"disk_size": true, "image": true, "size": true,
	}
)

type DriftDetector struct {
	IgnoreRules    []*models.IgnoreRule
	BaselineDrifts map[string]bool
}

func NewDetector(ignoreRules []*models.IgnoreRule, baselineDrifts map[string]bool) *DriftDetector {
	if baselineDrifts == nil {
		baselineDrifts = make(map[string]bool)
	}
	return &DriftDetector{
		IgnoreRules:    ignoreRules,
		BaselineDrifts: baselineDrifts,
	}
}

func (d *DriftDetector) shouldIgnore(resourceType, resourceName, attrPath string) bool {
	for _, rule := range d.IgnoreRules {
		if rule.Matches(resourceType, resourceName, attrPath) {
			return true
		}
	}
	return false
}

func (d *DriftDetector) isBaselineDrift(key string) bool {
	return d.BaselineDrifts[key]
}

func makeDriftKey(drift *models.DriftItem) string {
	return fmt.Sprintf("%s::%s::%s", drift.ResourceAddr, drift.DriftType, drift.AttributePath)
}

func isMetaAttribute(key string) bool {
	if strings.HasPrefix(key, "_") || strings.HasPrefix(key, "terraform_") {
		return true
	}
	knownMeta := map[string]bool{
		"id": true, "create_time": true, "created_at": true,
		"destroy_time": true, "template_name": true,
		"schema_version": true, "raw_configuration": true,
	}
	return knownMeta[key]
}

func isComputedAttribute(key string, resource *models.TfResource) bool {
	if resource.ComputedKeys != nil && resource.ComputedKeys[key] {
		return true
	}
	parts := strings.Split(key, ".")
	last := parts[len(parts)-1]
	return computedAttrs[last]
}

func valuesEqual(configVal, stateVal interface{}, key string) bool {
	if configVal == nil && stateVal == nil {
		return true
	}
	if configVal == nil || stateVal == nil {
		return false
	}

	configMap, configIsMap := configVal.(map[string]interface{})
	stateMap, stateIsMap := stateVal.(map[string]interface{})
	if configIsMap && stateIsMap {
		return mapsEqual(configMap, stateMap)
	}

	configList, configIsList := configVal.([]interface{})
	stateList, stateIsList := stateVal.([]interface{})
	if configIsList && stateIsList {
		return listsEqual(configList, stateList, key)
	}

	cfgStr, cfgIsStr := configVal.(string)
	stNum, stIsNum := stateVal.(float64)
	if cfgIsStr && stIsNum {
		if n, err := strconv.ParseFloat(cfgStr, 64); err == nil {
			return n == stNum
		}
	}

	stStr, stIsStr := stateVal.(string)
	cfgNum, cfgIsNum := configVal.(float64)
	if stIsStr && cfgIsNum {
		if n, err := strconv.ParseFloat(stStr, 64); err == nil {
			return n == cfgNum
		}
	}

	return fmt.Sprintf("%v", configVal) == fmt.Sprintf("%v", stateVal)
}

func mapsEqual(a, b map[string]interface{}) bool {
	allKeys := make(map[string]bool)
	for k := range a {
		allKeys[k] = true
	}
	for k := range b {
		allKeys[k] = true
	}
	for k := range allKeys {
		if !valuesEqual(a[k], b[k], k) {
			return false
		}
	}
	return true
}

func listsEqual(a, b []interface{}, key string) bool {
	if len(a) != len(b) {
		return false
	}

	hasUniqueID := false
	for _, item := range a {
		if m, ok := item.(map[string]interface{}); ok {
			if _, hasName := m["name"]; hasName {
				hasUniqueID = true
				break
			}
			if _, hasID := m["id"]; hasID {
				hasUniqueID = true
				break
			}
		}
	}

	if hasUniqueID {
		return listsEqualByID(a, b)
	}

	for i := range a {
		if !valuesEqual(a[i], b[i], key) {
			return false
		}
	}
	return true
}

func listsEqualByID(a, b []interface{}) bool {
	aMap := make(map[string]interface{})
	for _, item := range a {
		if m, ok := item.(map[string]interface{}); ok {
			if name, has := m["name"].(string); has {
				aMap[name] = item
			} else if id, has := m["id"].(string); has {
				aMap[id] = item
			}
		}
	}
	bMap := make(map[string]interface{})
	for _, item := range b {
		if m, ok := item.(map[string]interface{}); ok {
			if name, has := m["name"].(string); has {
				bMap[name] = item
			} else if id, has := m["id"].(string); has {
				bMap[id] = item
			}
		}
	}

	if len(aMap) != len(bMap) {
		return false
	}
	for k := range aMap {
		if _, ok := bMap[k]; !ok {
			return false
		}
	}
	for k := range aMap {
		if !valuesEqual(aMap[k], bMap[k], k) {
			return false
		}
	}
	return true
}

type expandedAttrs struct {
	flat   map[string]interface{}
	nested map[string]interface{}
}

func expandHclBlock(block *models.HclBlock) expandedAttrs {
	flat := make(map[string]interface{})
	nested := make(map[string]interface{})
	expandHclRecursive(block, "", flat, nested)
	return expandedAttrs{flat: flat, nested: nested}
}

func expandHclRecursive(block *models.HclBlock, prefix string, flat, nested map[string]interface{}) {
	for k, attr := range block.Attributes {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}

		if nestedMap, ok := attr.Value.(map[string]interface{}); ok && !attr.IsExpression {
			nested[fullKey] = nestedMap
			flat[fullKey] = nestedMap
			for nk, nv := range nestedMap {
				nestedFullKey := fullKey + "." + nk
				flat[nestedFullKey] = nv
			}
			expandNestedMap(nestedMap, fullKey, flat)
		} else {
			nested[fullKey] = attr.Value
			flat[fullKey] = attr.Value
		}
	}

	for _, nb := range block.NestedBlocks {
		nestedPrefix := nb.BlockType
		if prefix != "" {
			nestedPrefix = prefix + "." + nestedPrefix
		}
		for _, label := range nb.Labels {
			nestedPrefix = nestedPrefix + "." + label
		}
		expandHclRecursive(nb, nestedPrefix, flat, nested)
	}
}

func expandNestedMap(m map[string]interface{}, prefix string, flat map[string]interface{}) {
	for k, v := range m {
		fullKey := prefix + "." + k
		flat[fullKey] = v
		if nested, ok := v.(map[string]interface{}); ok {
			expandNestedMap(nested, fullKey, flat)
		}
	}
}

func expandStateAttributes(attrs map[string]interface{}) expandedAttrs {
	flat := make(map[string]interface{})
	nested := make(map[string]interface{})
	expandStateRecursive(attrs, "", flat, nested)
	return expandedAttrs{flat: flat, nested: nested}
}

func expandStateRecursive(attrs map[string]interface{}, prefix string, flat, nested map[string]interface{}) {
	for k, v := range attrs {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		if nestedMap, ok := v.(map[string]interface{}); ok {
			nested[fullKey] = nestedMap
			flat[fullKey] = nestedMap
			for nk, nv := range nestedMap {
				nestedFullKey := fullKey + "." + nk
				flat[nestedFullKey] = nv
			}
			expandStateRecursive(nestedMap, fullKey, flat, nested)
		} else {
			flat[fullKey] = v
			nested[fullKey] = v
		}
	}
}

func matchConfigKey(configKey string, stateFlat map[string]interface{}) (string, bool) {
	if _, ok := stateFlat[configKey]; ok {
		return configKey, true
	}
	for stateKey := range stateFlat {
		if strings.HasSuffix(stateKey, "."+configKey) {
			return stateKey, true
		}
	}
	return "", false
}

func (d *DriftDetector) assessRisk(drift *models.DriftItem, resourceType string) models.RiskLevel {
	switch drift.DriftType {
	case models.DriftResourceMissing:
		return models.RiskHigh
	case models.DriftOrphanResource:
		return models.RiskMedium
	case models.DriftAttributeChanged:
		attrName := drift.AttributePath
		parts := strings.Split(attrName, ".")
		last := parts[len(parts)-1]
		if rebuildTriggeringAttrs[last] {
			return models.RiskHigh
		}
		return models.RiskLow
	case models.DriftTypeMismatch:
		return models.RiskMedium
	case models.DriftAttributeMissing:
		return models.RiskMedium
	case models.DriftExtraAttribute:
		return models.RiskLow
	}
	return models.RiskLow
}

func (d *DriftDetector) Detect(
	stateResources map[string]*models.TfResource,
	config *models.HclConfig,
	depGraph *models.DependencyGraph,
) *models.DriftReport {

	report := models.NewDriftReport("", "", "")

	report.TotalResourcesInState = len(stateResources)
	report.TotalResourcesInConfig = len(config.Resources)

	stateByTypeName := make(map[string][]*models.TfResource)
	for _, res := range stateResources {
		key := res.ResourceType + "." + res.ResourceName
		stateByTypeName[key] = append(stateByTypeName[key], res)
	}

	configTypeName := make(map[string]bool)
	for k := range config.Resources {
		configTypeName[k] = true
	}

	for configKey, configBlock := range config.Resources {
		if len(configBlock.Labels) < 2 {
			continue
		}
		resourceType := configBlock.Labels[0]
		resourceName := configBlock.Labels[1]

		if d.shouldIgnore(resourceType, resourceName, "") {
			continue
		}

		stateMatches := stateByTypeName[configKey]
		configForEach := configBlock.ForEachExpr != ""
		configCount := configBlock.CountExpr != ""

		if len(stateMatches) == 0 {
			if !configForEach && !configCount {
				drift := &models.DriftItem{
					DriftType:     models.DriftResourceMissing,
					ResourceAddr:  configKey,
					AttributePath: "*",
					ConfigValue:   "<defined in config>",
					StateValue:    "<not found in state>",
					RiskLevel:     models.RiskHigh,
				}
				result := &models.DriftResult{
					ResourceAddr: configKey,
					ResourceType: resourceType,
					Drifts:       []*models.DriftItem{drift},
					MaxRisk:      models.RiskHigh,
				}
				report.Results = append(report.Results, result)
			}
			continue
		}

		for _, stateRes := range stateMatches {
			result := d.compareResource(stateRes, configBlock)
			if len(result.Drifts) > 0 {
				result.ComputeMaxRisk()
				report.Results = append(report.Results, result)
			}
		}
	}

	for _, stateRes := range stateResources {
		stateKey := stateRes.ResourceType + "." + stateRes.ResourceName
		if configTypeName[stateKey] {
			continue
		}
		if d.shouldIgnore(stateRes.ResourceType, stateRes.ResourceName, "") {
			continue
		}
		drift := &models.DriftItem{
			DriftType:     models.DriftOrphanResource,
			ResourceAddr:  stateRes.FullAddress(),
			AttributePath: "*",
			ConfigValue:   "<not defined in config>",
			StateValue:    "<exists in state>",
			RiskLevel:     models.RiskMedium,
		}
		result := &models.DriftResult{
			ResourceAddr: stateRes.FullAddress(),
			ResourceType: stateRes.ResourceType,
			Drifts:       []*models.DriftItem{drift},
			MaxRisk:      models.RiskMedium,
		}
		report.Results = append(report.Results, result)
	}

	report.ComputeSummary()
	return report
}

func (d *DriftDetector) compareResource(
	stateRes *models.TfResource,
	configBlock *models.HclBlock,
) *models.DriftResult {
	result := &models.DriftResult{
		ResourceAddr: stateRes.FullAddress(),
		ResourceType: stateRes.ResourceType,
	}

	configExpanded := expandHclBlock(configBlock)
	stateExpanded := expandStateAttributes(stateRes.Attributes)

	resourceType := stateRes.ResourceType
	resourceName := stateRes.ResourceName

	for configKey, configVal := range configExpanded.flat {
		if isMetaAttribute(configKey) {
			continue
		}

		if d.shouldIgnore(resourceType, resourceName, configKey) {
			continue
		}

		matchedStateKey, matched := matchConfigKey(configKey, stateExpanded.flat)

		if !matched {
			exprVal, isExpr := configVal.(string)
			if isExpr && (strings.HasPrefix(exprVal, "var.") ||
				strings.HasPrefix(exprVal, "local.") ||
				strings.HasPrefix(exprVal, "data.") ||
				strings.HasPrefix(exprVal, "module.") ||
				strings.Contains(exprVal, "${")) {
				continue
			}

			drift := &models.DriftItem{
				DriftType:     models.DriftAttributeMissing,
				ResourceAddr:  stateRes.FullAddress(),
				AttributePath: configKey,
				ConfigValue:   configVal,
				StateValue:    "<not present>",
				RiskLevel:     models.RiskMedium,
			}
			drift.RiskLevel = d.assessRisk(drift, resourceType)
			if !d.isBaselineDrift(makeDriftKey(drift)) {
				result.Drifts = append(result.Drifts, drift)
			}
			continue
		}

		stateVal := stateExpanded.flat[matchedStateKey]

		if isComputedAttribute(configKey, stateRes) {
			continue
		}

		if strVal, isStr := configVal.(string); isStr {
			if strings.HasPrefix(strVal, "var.") ||
				strings.HasPrefix(strVal, "local.") ||
				strings.HasPrefix(strVal, "data.") ||
				strings.HasPrefix(strVal, "module.") ||
				strings.Contains(strVal, "${") {
				continue
			}
		}

		configType := models.TypeName(configVal)
		stateType := models.TypeName(stateVal)

		if configVal != nil && stateVal != nil && configType != stateType {
			if !valuesEqual(configVal, stateVal, configKey) {
				if !((configType == "int" || configType == "float") && (stateType == "int" || stateType == "float")) {
					drift := &models.DriftItem{
						DriftType:     models.DriftTypeMismatch,
						ResourceAddr:  stateRes.FullAddress(),
						AttributePath: configKey,
						ConfigValue:   configVal,
						StateValue:    stateVal,
						ExpectedType:  configType,
						ActualType:    stateType,
						RiskLevel:     models.RiskMedium,
					}
					drift.RiskLevel = d.assessRisk(drift, resourceType)
					if !d.isBaselineDrift(makeDriftKey(drift)) {
						result.Drifts = append(result.Drifts, drift)
					}
					continue
				}
			}
		}

		if !valuesEqual(configVal, stateVal, configKey) {
			drift := &models.DriftItem{
				DriftType:     models.DriftAttributeChanged,
				ResourceAddr:  stateRes.FullAddress(),
				AttributePath: configKey,
				ConfigValue:   configVal,
				StateValue:    stateVal,
				RiskLevel:     models.RiskLow,
			}
			drift.RiskLevel = d.assessRisk(drift, resourceType)
			if !d.isBaselineDrift(makeDriftKey(drift)) {
				result.Drifts = append(result.Drifts, drift)
			}
		}
	}

	for stateKey, stateVal := range stateExpanded.flat {
		if isMetaAttribute(stateKey) {
			continue
		}
		if stateRes.SensitiveKeys != nil && stateRes.SensitiveKeys[stateKey] {
			continue
		}
		if isComputedAttribute(stateKey, stateRes) {
			continue
		}

		_, flatMatched := configExpanded.flat[stateKey]
		_, nestedMatched := configExpanded.nested[stateKey]
		if flatMatched || nestedMatched {
			continue
		}

		if d.shouldIgnore(resourceType, resourceName, stateKey) {
			continue
		}

		drift := &models.DriftItem{
			DriftType:     models.DriftExtraAttribute,
			ResourceAddr:  stateRes.FullAddress(),
			AttributePath: stateKey,
			ConfigValue:   "<not declared>",
			StateValue:    stateVal,
			RiskLevel:     models.RiskLow,
		}
		drift.RiskLevel = d.assessRisk(drift, resourceType)
		if !d.isBaselineDrift(makeDriftKey(drift)) {
			result.Drifts = append(result.Drifts, drift)
		}
	}

	return result
}

func RunDetection(
	stateFile, configDir, workspace string,
	ignoreRules []*models.IgnoreRule,
	baselineDrifts map[string]bool,
) (*models.DriftReport, *models.DependencyGraph, error) {

	stateResources, depGraph, err := tfstate.ParseFile(stateFile, workspace)
	if err != nil {
		return nil, nil, err
	}

	config, err := hcl.ParseDir(configDir)
	if err != nil {
		return nil, nil, err
	}

	detector := NewDetector(ignoreRules, baselineDrifts)
	report := detector.Detect(stateResources, config, depGraph)
	report.StateFile = stateFile
	report.ConfigDir = configDir
	report.Workspace = workspace

	return report, depGraph, nil
}

func LoadBaseline(path string) (map[string]bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return make(map[string]bool), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return make(map[string]bool), err
	}
	var raw struct {
		DriftKeys []string `json:"drift_keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return make(map[string]bool), err
	}
	result := make(map[string]bool)
	for _, k := range raw.DriftKeys {
		result[k] = true
	}
	return result, nil
}

func SaveBaseline(report *models.DriftReport, path string) error {
	driftKeys := []string{}
	for _, result := range report.Results {
		for _, drift := range result.Drifts {
			driftKeys = append(driftKeys, makeDriftKey(drift))
		}
	}
	baseline := map[string]interface{}{
		"timestamp":  report.Timestamp,
		"state_file": report.StateFile,
		"config_dir": report.ConfigDir,
		"drift_keys": driftKeys,
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
