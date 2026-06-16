package models

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

const ToolVersion = "0.1.0"

type ReportMetadata struct {
	ToolVersion  string
	Timestamp    string
	Command      string
	StateFileAbs string
	ConfigDirAbs string
	GoVersion    string
}

func NewReportMetadata(stateFileAbs, configDirAbs string) *ReportMetadata {
	return &ReportMetadata{
		ToolVersion:  ToolVersion,
		Timestamp:    time.Now().Format(time.RFC3339),
		Command:      strings.Join(getCommandArgs(), " "),
		StateFileAbs: stateFileAbs,
		ConfigDirAbs: configDirAbs,
		GoVersion:    runtime.Version(),
	}
}

func getCommandArgs() []string {
	if len(os.Args) > 0 {
		return os.Args[1:]
	}
	return []string{}
}

type DriftType string

const (
	DriftAttributeChanged  DriftType = "attribute_changed"
	DriftAttributeMissing  DriftType = "attribute_missing"
	DriftExtraAttribute    DriftType = "extra_attribute"
	DriftResourceMissing   DriftType = "resource_missing"
	DriftOrphanResource    DriftType = "orphan_resource"
	DriftTypeMismatch      DriftType = "type_mismatch"
)

type RiskLevel string

const (
	RiskHigh   RiskLevel = "high"
	RiskMedium RiskLevel = "medium"
	RiskLow    RiskLevel = "low"
)

func (r RiskLevel) Order() int {
	switch r {
	case RiskHigh:
		return 0
	case RiskMedium:
		return 1
	default:
		return 2
	}
}

func (d DriftType) SeverityOrder() int {
	switch d {
	case DriftResourceMissing:
		return 0
	case DriftOrphanResource:
		return 1
	case DriftAttributeChanged:
		return 2
	case DriftTypeMismatch:
		return 3
	case DriftAttributeMissing:
		return 4
	case DriftExtraAttribute:
		return 5
	default:
		return 99
	}
}

func (d DriftType) Label() string {
	switch d {
	case DriftAttributeChanged:
		return "CHANGED"
	case DriftAttributeMissing:
		return "MISSING"
	case DriftExtraAttribute:
		return "EXTRA"
	case DriftResourceMissing:
		return "RESOURCE MISSING"
	case DriftOrphanResource:
		return "ORPHAN"
	case DriftTypeMismatch:
		return "TYPE MISMATCH"
	default:
		return string(d)
	}
}

type ResourceRef struct {
	RefType      string
	ModulePath   string
	ResourceType string
	ResourceName string
	Attribute    string
	Raw          string
}

func (r *ResourceRef) Address() string {
	parts := []string{}
	if r.ModulePath != "" {
		parts = append(parts, "module."+r.ModulePath)
	}
	if r.ResourceType != "" && r.ResourceName != "" {
		parts = append(parts, r.ResourceType+"."+r.ResourceName)
	}
	if r.Attribute != "" {
		parts = append(parts, r.Attribute)
	}
	if len(parts) > 0 {
		return strings.Join(parts, ".")
	}
	return r.Raw
}

type TfResource struct {
	Address            string
	ResourceType       string
	ResourceName       string
	Provider           string
	ModulePath         string
	Index              interface{}
	IndexStr           string
	Attributes         map[string]interface{}
	SensitiveKeys      map[string]bool
	DependsOn          []string
	References         []ResourceRef
	CreateTime         string
	ResourceID         string
	IsForEach          bool
	IsCount            bool
	ForEachKey         string
	ComputedKeys       map[string]bool
	ProviderName       string
	IsUnknownProvider  bool
}

func (r *TfResource) FullAddress() string {
	base := r.ResourceType + "." + r.ResourceName
	if r.ModulePath != "" {
		base = "module." + r.ModulePath + "." + base
	}
	if r.IndexStr != "" {
		base += "[" + r.IndexStr + "]"
	}
	return base
}

type HclAttribute struct {
	Key            string
	Value          interface{}
	IsExpression   bool
	ExpressionText string
	References     []ResourceRef
	IsDynamic      bool
	IsConditional  bool
}

type HclBlock struct {
	BlockType     string
	Labels        []string
	Attributes    map[string]*HclAttribute
	NestedBlocks  []*HclBlock
	SourceFile    string
	SourceLine    int
	ForEachExpr   string
	CountExpr     string
	Provider      string
	DependsOn     []string
	IsDynamic     bool
}

func (b *HclBlock) Address() string {
	if b.BlockType == "resource" && len(b.Labels) >= 2 {
		return b.Labels[0] + "." + b.Labels[1]
	}
	return strings.Join(b.Labels, ".")
}

type HclConfig struct {
	Resources   map[string]*HclBlock
	DataSources map[string]*HclBlock
	Variables   map[string]*HclBlock
	Locals      map[string]*HclAttribute
	Outputs     map[string]*HclBlock
	Modules     map[string]*HclBlock
	SourceFiles []string
}

func NewHclConfig() *HclConfig {
	return &HclConfig{
		Resources:   make(map[string]*HclBlock),
		DataSources: make(map[string]*HclBlock),
		Variables:   make(map[string]*HclBlock),
		Locals:      make(map[string]*HclAttribute),
		Outputs:     make(map[string]*HclBlock),
		Modules:     make(map[string]*HclBlock),
	}
}

type DriftItem struct {
	DriftType      DriftType
	ResourceAddr   string
	AttributePath  string
	ConfigValue    interface{}
	StateValue     interface{}
	ExpectedType   string
	ActualType     string
	RiskLevel      RiskLevel
	IsComputed     bool
	IsNested       bool
}

type ImpactNode struct {
	ResourceAddr     string
	Level            int
	PropagationPath  []string
	DriftAttribute   string
}

type RemediationOption struct {
	Action        string
	Description   string
	Command       string
	Risk          string
	Note          string
	Condition     string `json:"condition,omitempty"`
	Timeout       int    `json:"timeout,omitempty"`
	PostCondition string `json:"post_condition,omitempty"`
}

type Remediation struct {
	DriftType     string
	Resource      string
	Attribute     string
	ConfigValue   string
	StateValue    string
	ExpectedType  string
	ActualType    string
	Options       []RemediationOption
	Recommended   *RemediationOption
	RiskLevel     string
}

type DriftResult struct {
	ResourceAddr      string
	ResourceType      string
	Drifts            []*DriftItem
	ImpactedResources []*ImpactNode
	Remediations      []*Remediation
	MaxRisk           RiskLevel
}

func (r *DriftResult) ComputeMaxRisk() {
	if len(r.Drifts) == 0 {
		r.MaxRisk = RiskLow
		return
	}
	maxOrder := 3
	for _, d := range r.Drifts {
		if d.RiskLevel.Order() < maxOrder {
			maxOrder = d.RiskLevel.Order()
			r.MaxRisk = d.RiskLevel
		}
	}
}

type DriftReport struct {
	Metadata               *ReportMetadata
	Timestamp              string
	StateFile              string
	ConfigDir              string
	Workspace              string
	Results                []*DriftResult
	TotalResourcesInState  int
	TotalResourcesInConfig int
	TotalDrifts            int
	HighRiskCount          int
	MediumRiskCount        int
	LowRiskCount           int
	BaselineFile           string
	IgnoredCount           int
	EnvironmentDiffs       []map[string]interface{}
}

func NewDriftReport(stateFile, configDir, workspace string) *DriftReport {
	return &DriftReport{
		Timestamp: time.Now().Format(time.RFC3339),
		StateFile: stateFile,
		ConfigDir: configDir,
		Workspace: workspace,
	}
}

func (r *DriftReport) ComputeSummary() {
	r.TotalDrifts = 0
	r.HighRiskCount = 0
	r.MediumRiskCount = 0
	r.LowRiskCount = 0
	for _, res := range r.Results {
		r.TotalDrifts += len(res.Drifts)
		for _, d := range res.Drifts {
			switch d.RiskLevel {
			case RiskHigh:
				r.HighRiskCount++
			case RiskMedium:
				r.MediumRiskCount++
			default:
				r.LowRiskCount++
			}
		}
	}
}

func (r *DriftReport) SortResults() {
	sort.Slice(r.Results, func(i, j int) bool {
		ri := r.Results[i].MaxRisk.Order()
		rj := r.Results[j].MaxRisk.Order()
		if ri != rj {
			return ri < rj
		}
		return r.Results[i].ResourceAddr < r.Results[j].ResourceAddr
	})
	for _, res := range r.Results {
		sort.Slice(res.Drifts, func(i, j int) bool {
			di := res.Drifts[i].DriftType.SeverityOrder()
			dj := res.Drifts[j].DriftType.SeverityOrder()
			if di != dj {
				return di < dj
			}
			return res.Drifts[i].AttributePath < res.Drifts[j].AttributePath
		})
	}
}

type ReportOptions struct {
	GroupBy string
	MinRisk RiskLevel
	Sort    string
}

type GroupResult struct {
	GroupName   string
	Results     []*DriftResult
	ResourceCnt int
	DriftCnt    int
}

func NewReportOptions() *ReportOptions {
	return &ReportOptions{
		GroupBy: "none",
		MinRisk: RiskLow,
		Sort:    "risk",
	}
}

func (r *DriftReport) FilterByRisk(minRisk RiskLevel) *DriftReport {
	filtered := &DriftReport{
		Metadata:               r.Metadata,
		Timestamp:              r.Timestamp,
		StateFile:              r.StateFile,
		ConfigDir:              r.ConfigDir,
		Workspace:              r.Workspace,
		TotalResourcesInState:  r.TotalResourcesInState,
		TotalResourcesInConfig: r.TotalResourcesInConfig,
		BaselineFile:           r.BaselineFile,
		IgnoredCount:           r.IgnoredCount,
		EnvironmentDiffs:       r.EnvironmentDiffs,
	}

	minOrder := minRisk.Order()
	for _, res := range r.Results {
		var filteredDrifts []*DriftItem
		keptAttrs := make(map[string]bool)
		for _, d := range res.Drifts {
			if d.RiskLevel.Order() <= minOrder {
				filteredDrifts = append(filteredDrifts, d)
				keptAttrs[d.AttributePath] = true
			}
		}
		if len(filteredDrifts) > 0 {
			var filteredRems []*Remediation
			for _, rem := range res.Remediations {
				if rem.Attribute == "*" {
					var hasMatchingDrift bool
					for _, d := range filteredDrifts {
						if d.DriftType == DriftResourceMissing || d.DriftType == DriftOrphanResource {
							hasMatchingDrift = true
							break
						}
					}
					if hasMatchingDrift {
						filteredRems = append(filteredRems, rem)
					}
				} else if keptAttrs[rem.Attribute] {
					filteredRems = append(filteredRems, rem)
				}
			}

			newRes := &DriftResult{
				ResourceAddr:      res.ResourceAddr,
				ResourceType:      res.ResourceType,
				Drifts:            filteredDrifts,
				ImpactedResources: res.ImpactedResources,
				Remediations:      filteredRems,
			}
			newRes.ComputeMaxRisk()
			filtered.Results = append(filtered.Results, newRes)
		}
	}

	filtered.ComputeSummary()
	return filtered
}

func (r *DriftReport) SortResultsCustom(sortMode string) {
	switch sortMode {
	case "count":
		sort.Slice(r.Results, func(i, j int) bool {
			ci := len(r.Results[i].Drifts)
			cj := len(r.Results[j].Drifts)
			if ci != cj {
				return ci > cj
			}
			ri := r.Results[i].MaxRisk.Order()
			rj := r.Results[j].MaxRisk.Order()
			if ri != rj {
				return ri < rj
			}
			return r.Results[i].ResourceAddr < r.Results[j].ResourceAddr
		})
	default:
		sort.Slice(r.Results, func(i, j int) bool {
			ri := r.Results[i].MaxRisk.Order()
			rj := r.Results[j].MaxRisk.Order()
			if ri != rj {
				return ri < rj
			}
			return r.Results[i].ResourceAddr < r.Results[j].ResourceAddr
		})
	}

	for _, res := range r.Results {
		sort.Slice(res.Drifts, func(i, j int) bool {
			di := res.Drifts[i].DriftType.SeverityOrder()
			dj := res.Drifts[j].DriftType.SeverityOrder()
			if di != dj {
				return di < dj
			}
			return res.Drifts[i].AttributePath < res.Drifts[j].AttributePath
		})
	}
}

func (r *DriftReport) GroupResults(groupBy string) []*GroupResult {
	if groupBy != "resource_type" && groupBy != "module" {
		return nil
	}

	groupMap := make(map[string]*GroupResult)
	var groupOrder []string

	for _, res := range r.Results {
		var groupKey string
		switch groupBy {
		case "resource_type":
			groupKey = res.ResourceType
			if groupKey == "" {
				groupKey = "unknown"
			}
		case "module":
			addr := res.ResourceAddr
			if strings.HasPrefix(addr, "module.") {
				parts := strings.SplitN(addr, ".", 3)
				if len(parts) >= 2 {
					groupKey = "module." + parts[1]
				} else {
					groupKey = "root"
				}
			} else {
				groupKey = "root"
			}
		}

		if _, exists := groupMap[groupKey]; !exists {
			groupMap[groupKey] = &GroupResult{
				GroupName: groupKey,
				Results:   []*DriftResult{},
			}
			groupOrder = append(groupOrder, groupKey)
		}
		groupMap[groupKey].Results = append(groupMap[groupKey].Results, res)
		groupMap[groupKey].ResourceCnt++
		groupMap[groupKey].DriftCnt += len(res.Drifts)
	}

	sort.Slice(groupOrder, func(i, j int) bool {
		gi := groupMap[groupOrder[i]]
		gj := groupMap[groupOrder[j]]
		if gi.DriftCnt != gj.DriftCnt {
			return gi.DriftCnt > gj.DriftCnt
		}
		return gi.GroupName < gj.GroupName
	})

	result := make([]*GroupResult, len(groupOrder))
	for i, key := range groupOrder {
		grp := groupMap[key]
		sort.Slice(grp.Results, func(a, b int) bool {
			ra := grp.Results[a].MaxRisk.Order()
			rb := grp.Results[b].MaxRisk.Order()
			if ra != rb {
				return ra < rb
			}
			return grp.Results[a].ResourceAddr < grp.Results[b].ResourceAddr
		})
		result[i] = grp
	}
	return result
}

type EnvironmentDiff struct {
	ResourceAddr     string
	AttributePath    string
	Values           map[string]interface{}
	IsProductionUnique bool
}

type IgnoreRule struct {
	ResourceType   string
	ResourceName   string
	AttributeName  string
	Tags           map[string]string
}

func (r *IgnoreRule) Matches(resourceType, resourceName, attrPath string) bool {
	if r.ResourceType != "" {
		if r.ResourceType == "*" {
		} else if !strings.HasSuffix(resourceType, r.ResourceType) && !strings.HasPrefix(r.ResourceType, resourceType) && r.ResourceType != resourceType {
			return false
		}
	}
	if r.ResourceName != "" {
		if r.ResourceName == "*" {
		} else if r.ResourceName != resourceName {
			return false
		}
	}
	if r.AttributeName != "" && attrPath != "" {
		if r.AttributeName == "*" {
		} else if r.AttributeName != attrPath {
			return false
		}
	}
	return true
}

func ParseIgnoreRule(spec string) *IgnoreRule {
	rule := &IgnoreRule{}
	if strings.Contains(spec, ".*.") {
		parts := strings.SplitN(spec, ".", 3)
		if len(parts) >= 2 {
			rule.ResourceType = parts[0]
			if parts[1] == "*" {
				rule.ResourceName = "*"
			} else {
				rule.ResourceName = parts[1]
			}
			if len(parts) == 3 {
				rule.AttributeName = parts[2]
			}
		}
	} else if strings.HasSuffix(spec, ".*") {
		rule.ResourceType = strings.TrimSuffix(spec, ".*")
		rule.ResourceName = "*"
	} else if strings.Contains(spec, ".") {
		parts := strings.SplitN(spec, ".", 3)
		if len(parts) >= 2 {
			rule.ResourceType = parts[0]
			rule.ResourceName = parts[1]
			if len(parts) == 3 {
				rule.AttributeName = parts[2]
			}
		}
	} else {
		rule.ResourceType = spec
	}
	return rule
}

type DriftConfig struct {
	IgnoreRules        []*IgnoreRule
	DefaultFormat      string
	ExitCodeThreshold  string
	StateFile          string
	ConfigDir          string
	Workspace          string
}

func NewDriftConfig() *DriftConfig {
	return &DriftConfig{
		DefaultFormat:     "terminal",
		ExitCodeThreshold: "any",
		IgnoreRules:       []*IgnoreRule{},
	}
}

type FlattenedAttr map[string]interface{}

func FlattenStateAttributes(attrs map[string]interface{}) FlattenedAttr {
	result := make(FlattenedAttr)
	flattenAttrsRecursive(attrs, "", result)
	return result
}

func flattenAttrsRecursive(attrs map[string]interface{}, prefix string, result FlattenedAttr) {
	for k, v := range attrs {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		nested, ok := v.(map[string]interface{})
		if ok {
			flattenAttrsRecursive(nested, fullKey, result)
		} else {
			result[fullKey] = v
		}
	}
}

func FlattenHclBlock(block *HclBlock) FlattenedAttr {
	result := make(FlattenedAttr)
	flattenHclRecursive(block, "", result)
	return result
}

func flattenHclRecursive(block *HclBlock, prefix string, result FlattenedAttr) {
	for k, attr := range block.Attributes {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		nested, ok := attr.Value.(map[string]interface{})
		if ok && !attr.IsExpression {
			result[fullKey] = nested
			for nk, nv := range nested {
				nestedFullKey := fullKey + "." + nk
				result[nestedFullKey] = nv
			}
		} else {
			result[fullKey] = attr.Value
		}
	}
	for _, nested := range block.NestedBlocks {
		nestedPrefix := nested.BlockType
		if prefix != "" {
			nestedPrefix = prefix + "." + nested.BlockType
		}
		for _, label := range nested.Labels {
			nestedPrefix = nestedPrefix + "." + label
		}
		flattenHclRecursive(nested, nestedPrefix, result)
	}
}

func SerializeValue(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case string:
		return val
	case int, int64, float64, bool:
		return fmt.Sprintf("%v", val)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func TypeName(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch v.(type) {
	case bool:
		return "bool"
	case int, int64:
		return "int"
	case float64:
		return "float"
	case string:
		return "string"
	case []interface{}:
		return "list"
	case map[string]interface{}:
		return "map"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func ToString(v interface{}) string {
	return fmt.Sprintf("%v", v)
}
