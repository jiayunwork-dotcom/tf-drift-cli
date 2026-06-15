package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
	"gopkg.in/yaml.v3"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

type Action string

const (
	ActionBlock Action = "block"
	ActionWarn  Action = "warn"
)

type DriftTypeCategory string

const (
	DriftCategoryChanged DriftTypeCategory = "changed"
	DriftCategoryMissing DriftTypeCategory = "missing"
	DriftCategoryExtra   DriftTypeCategory = "extra"
	DriftCategoryOrphan  DriftTypeCategory = "orphan"
)

type ConditionMode string

const (
	ConditionModeAll ConditionMode = "all"
	ConditionModeAny ConditionMode = "any"
)

type SubCondition struct {
	ResourceTypes []string `yaml:"resource_types"`
	Attributes    []string `yaml:"attributes"`
	DriftTypes    []string `yaml:"drift_types"`
}

type PolicyMatch struct {
	ConditionMode ConditionMode  `yaml:"condition_mode"`
	ResourceTypes []string       `yaml:"resource_types"`
	Attributes    []string       `yaml:"attributes"`
	DriftTypes    []string       `yaml:"drift_types"`
	SubConditions []SubCondition `yaml:"sub_conditions"`
}

type Policy struct {
	ID       string      `yaml:"id"`
	Name     string      `yaml:"name"`
	Severity Severity    `yaml:"severity"`
	Match    PolicyMatch `yaml:"match"`
	Action   Action      `yaml:"action"`
}

type PolicyFile struct {
	Extends  string    `yaml:"extends"`
	Policies []*Policy `yaml:"policies"`
}

type rawPolicyFile struct {
	Extends  string    `yaml:"extends"`
	Policies []*Policy `yaml:"policies"`
}

type Violation struct {
	Policy        *Policy
	ResourceAddr  string
	AttributePath string
	DriftType     models.DriftType
	FromCache     bool
}

type ComplianceResult struct {
	ViolatedPolicies []*ViolatedPolicy
	HasCritical      bool
	CacheReused      int
	CacheReevaluated int
}

type ViolatedPolicy struct {
	PolicyID   string
	PolicyName string
	Severity   Severity
	Action     Action
	Violations []*ViolationItem
}

type ViolationItem struct {
	ResourceAddr  string
	AttributePath string
	DriftType     models.DriftType
	FromCache     bool
}

type PolicyCache struct {
	PolicyFileSHA256 string                      `json:"policy_file_sha256"`
	DriftFingerprints map[string][]string        `json:"drift_fingerprints"`
}

func severityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

func driftTypeToCategory(dt models.DriftType) DriftTypeCategory {
	switch dt {
	case models.DriftAttributeChanged, models.DriftTypeMismatch:
		return DriftCategoryChanged
	case models.DriftAttributeMissing, models.DriftResourceMissing:
		return DriftCategoryMissing
	case models.DriftExtraAttribute:
		return DriftCategoryExtra
	case models.DriftOrphanResource:
		return DriftCategoryOrphan
	default:
		return ""
	}
}

func computeDriftFingerprint(resourceAddr, attribute string, driftType models.DriftType) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s|%s|%s", resourceAddr, attribute, string(driftType))))
	return hex.EncodeToString(h.Sum(nil))
}

func ComputePolicyFileSHA256(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func LoadPolicyCache(path string) (*PolicyCache, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cache PolicyCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	if cache.DriftFingerprints == nil {
		cache.DriftFingerprints = make(map[string][]string)
	}
	return &cache, nil
}

func SavePolicyCache(path string, cache *PolicyCache) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0644)
}

type loadedPolicyFile struct {
	absPath  string
	relPath  string
	raw      *rawPolicyFile
	policies []*Policy
}

func LoadPolicyFile(path string) (*PolicyFile, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy path: %w", err)
	}

	loadedMap := make(map[string]*loadedPolicyFile)
	loadOrder := []string{}

	var loadRecursive func(currentPath string, ancestors []string) error
	loadRecursive = func(currentPath string, ancestors []string) error {
		absCurrent, err := filepath.Abs(currentPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path %s: %w", currentPath, err)
		}

		for _, anc := range ancestors {
			if anc == absCurrent {
				chain := append(ancestors, absCurrent)
				chainStr := make([]string, len(chain))
				for i, p := range chain {
					chainStr[i] = p
				}
				return fmt.Errorf("循环继承检测到: %s (退出码4)", strings.Join(chainStr, " -> "))
			}
		}

		if _, exists := loadedMap[absCurrent]; exists {
			return nil
		}

		data, err := os.ReadFile(absCurrent)
		if err != nil {
			return fmt.Errorf("failed to read policy file %s: %w", absCurrent, err)
		}

		var raw rawPolicyFile
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("failed to parse policy file %s: %w", absCurrent, err)
		}

		newAncestors := append(ancestors, absCurrent)

		loaded := &loadedPolicyFile{
			absPath:  absCurrent,
			relPath:  currentPath,
			raw:      &raw,
			policies: copyPolicies(raw.Policies),
		}

		if raw.Extends != "" {
			parentPath := raw.Extends
			if !filepath.IsAbs(parentPath) {
				parentPath = filepath.Join(filepath.Dir(absCurrent), parentPath)
			}
			if err := loadRecursive(parentPath, newAncestors); err != nil {
				return err
			}
		}

		loadedMap[absCurrent] = loaded
		loadOrder = append(loadOrder, absCurrent)
		return nil
	}

	if err := loadRecursive(absPath, []string{}); err != nil {
		return nil, err
	}

	mergedPolicies := []*Policy{}
	idOrder := []string{}
	idMap := make(map[string]*Policy)

	for _, absKey := range loadOrder {
		loaded := loadedMap[absKey]
		for _, p := range loaded.policies {
			if _, exists := idMap[p.ID]; !exists {
				idOrder = append(idOrder, p.ID)
			}
			idMap[p.ID] = p
		}
	}

	for _, id := range idOrder {
		mergedPolicies = append(mergedPolicies, idMap[id])
	}

	pf := &PolicyFile{
		Policies: mergedPolicies,
	}

	if err := pf.Validate(); err != nil {
		return nil, err
	}

	return pf, nil
}

func copyPolicies(src []*Policy) []*Policy {
	dst := make([]*Policy, len(src))
	for i, p := range src {
		newP := &Policy{
			ID:       p.ID,
			Name:     p.Name,
			Severity: p.Severity,
			Action:   p.Action,
			Match: PolicyMatch{
				ConditionMode: p.Match.ConditionMode,
				ResourceTypes: append([]string{}, p.Match.ResourceTypes...),
				Attributes:    append([]string{}, p.Match.Attributes...),
				DriftTypes:    append([]string{}, p.Match.DriftTypes...),
			},
		}
		if len(p.Match.SubConditions) > 0 {
			newP.Match.SubConditions = make([]SubCondition, len(p.Match.SubConditions))
			for j, sc := range p.Match.SubConditions {
				newP.Match.SubConditions[j] = SubCondition{
					ResourceTypes: append([]string{}, sc.ResourceTypes...),
					Attributes:    append([]string{}, sc.Attributes...),
					DriftTypes:    append([]string{}, sc.DriftTypes...),
				}
			}
		}
		dst[i] = newP
	}
	return dst
}

func (pf *PolicyFile) Validate() error {
	seenIDs := make(map[string]bool)

	for i, p := range pf.Policies {
		if p.ID == "" {
			return fmt.Errorf("policy #%d: id is required", i+1)
		}
		if seenIDs[p.ID] {
			return fmt.Errorf("policy #%d: duplicate id '%s'", i+1, p.ID)
		}
		seenIDs[p.ID] = true

		if p.Name == "" {
			return fmt.Errorf("policy '%s': name is required", p.ID)
		}

		switch p.Severity {
		case SeverityCritical, SeverityWarning, SeverityInfo:
		default:
			return fmt.Errorf("policy '%s': invalid severity '%s', must be one of: critical, warning, info", p.ID, p.Severity)
		}

		switch p.Action {
		case ActionBlock, ActionWarn:
		default:
			return fmt.Errorf("policy '%s': invalid action '%s', must be one of: block, warn", p.ID, p.Action)
		}

		condMode := p.Match.ConditionMode
		if condMode == "" {
			condMode = ConditionModeAll
		}
		switch condMode {
		case ConditionModeAll, ConditionModeAny:
		default:
			return fmt.Errorf("policy '%s': invalid condition_mode '%s', must be one of: all, any", p.ID, condMode)
		}

		if len(p.Match.SubConditions) > 0 {
			for j, sc := range p.Match.SubConditions {
				hasRT := len(sc.ResourceTypes) > 0
				hasAttr := len(sc.Attributes) > 0
				hasDT := len(sc.DriftTypes) > 0
				if !hasRT && !hasAttr && !hasDT {
					return fmt.Errorf("policy '%s': sub_condition #%d must have at least one of: resource_types, attributes, drift_types", p.ID, j+1)
				}
				for _, dt := range sc.DriftTypes {
					switch DriftTypeCategory(dt) {
					case DriftCategoryChanged, DriftCategoryMissing, DriftCategoryExtra, DriftCategoryOrphan:
					default:
						return fmt.Errorf("policy '%s': sub_condition #%d invalid drift_type '%s', must be one of: changed, missing, extra, orphan", p.ID, j+1, dt)
					}
				}
				if len(sc.ResourceTypes) > 0 {
					for _, scRT := range sc.ResourceTypes {
						_ = scRT
					}
				}
			}
		} else {
			hasResourceTypes := len(p.Match.ResourceTypes) > 0
			hasAttributes := len(p.Match.Attributes) > 0
			hasDriftTypes := len(p.Match.DriftTypes) > 0

			if !hasResourceTypes && !hasAttributes && !hasDriftTypes {
				return fmt.Errorf("policy '%s': match must have at least one of: resource_types, attributes, drift_types", p.ID)
			}

			for _, dt := range p.Match.DriftTypes {
				switch DriftTypeCategory(dt) {
				case DriftCategoryChanged, DriftCategoryMissing, DriftCategoryExtra, DriftCategoryOrphan:
				default:
					return fmt.Errorf("policy '%s': invalid drift_type '%s', must be one of: changed, missing, extra, orphan", p.ID, dt)
				}
			}
		}
	}

	return nil
}

func matchResourceTypes(patterns []string, resourceType string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, resourceType); ok {
			return true
		}
	}
	return false
}

func matchAttributes(patterns []string, attrPath string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, attrPath); ok {
			return true
		}
	}
	return false
}

func matchDriftTypes(patterns []string, dt models.DriftType) bool {
	if len(patterns) == 0 {
		return true
	}
	category := driftTypeToCategory(dt)
	for _, p := range patterns {
		if DriftTypeCategory(p) == category {
			return true
		}
	}
	return false
}

func matchSubCondition(sc *SubCondition, drift *models.DriftItem, resourceType string) bool {
	rtMatched := matchResourceTypes(sc.ResourceTypes, resourceType)
	attrMatched := matchAttributes(sc.Attributes, drift.AttributePath)
	dtMatched := matchDriftTypes(sc.DriftTypes, drift.DriftType)
	return rtMatched && attrMatched && dtMatched
}

func (p *Policy) Matches(drift *models.DriftItem, resourceType string) bool {
	condMode := p.Match.ConditionMode
	if condMode == "" {
		condMode = ConditionModeAll
	}

	if len(p.Match.SubConditions) > 0 {
		if condMode == ConditionModeAll {
			for i := range p.Match.SubConditions {
				if !matchSubCondition(&p.Match.SubConditions[i], drift, resourceType) {
					return false
				}
			}
			return true
		} else {
			for i := range p.Match.SubConditions {
				if matchSubCondition(&p.Match.SubConditions[i], drift, resourceType) {
					return true
				}
			}
			return false
		}
	}

	rtMatched := matchResourceTypes(p.Match.ResourceTypes, resourceType)
	attrMatched := matchAttributes(p.Match.Attributes, drift.AttributePath)
	dtMatched := matchDriftTypes(p.Match.DriftTypes, drift.DriftType)

	if condMode == ConditionModeAll {
		return rtMatched && attrMatched && dtMatched
	} else {
		return rtMatched || attrMatched || dtMatched
	}
}

func EvaluatePoliciesWithCache(
	report *models.DriftReport,
	policies []*Policy,
	cache *PolicyCache,
) (*ComplianceResult, *PolicyCache) {
	result := &ComplianceResult{
		ViolatedPolicies: []*ViolatedPolicy{},
	}

	newCache := &PolicyCache{
		DriftFingerprints: make(map[string][]string),
	}

	policyViolations := make(map[string][]*ViolationItem)
	policyMap := make(map[string]*Policy)
	policyIDs := make(map[string]bool)

	for _, p := range policies {
		policyMap[p.ID] = p
		policyIDs[p.ID] = true
	}

	cacheAvailable := cache != nil && cache.DriftFingerprints != nil

	for _, res := range report.Results {
		resourceType := res.ResourceType
		for _, drift := range res.Drifts {
			fp := computeDriftFingerprint(res.ResourceAddr, drift.AttributePath, drift.DriftType)

			cachedPolicyIDs := []string{}
			fromCache := false

			if cacheAvailable {
				if cids, ok := cache.DriftFingerprints[fp]; ok {
					validIDs := []string{}
					for _, pid := range cids {
						if policyIDs[pid] {
							validIDs = append(validIDs, pid)
						}
					}
					if len(validIDs) == len(cids) || len(cids) == 0 {
						cachedPolicyIDs = validIDs
						fromCache = true
					}
				}
			}

			matchedPolicyIDs := []string{}

			if fromCache {
				result.CacheReused++
				matchedPolicyIDs = cachedPolicyIDs
				for _, pid := range cachedPolicyIDs {
					item := &ViolationItem{
						ResourceAddr:  res.ResourceAddr,
						AttributePath: drift.AttributePath,
						DriftType:     drift.DriftType,
						FromCache:     true,
					}
					policyViolations[pid] = append(policyViolations[pid], item)
				}
			} else {
				result.CacheReevaluated++
				for _, p := range policies {
					if p.Matches(drift, resourceType) {
						matchedPolicyIDs = append(matchedPolicyIDs, p.ID)
						item := &ViolationItem{
							ResourceAddr:  res.ResourceAddr,
							AttributePath: drift.AttributePath,
							DriftType:     drift.DriftType,
							FromCache:     false,
						}
						policyViolations[p.ID] = append(policyViolations[p.ID], item)
					}
				}
			}

			if len(matchedPolicyIDs) > 0 {
				newCache.DriftFingerprints[fp] = matchedPolicyIDs
			} else {
				newCache.DriftFingerprints[fp] = []string{}
			}
		}
	}

	for policyID, violations := range policyViolations {
		p := policyMap[policyID]
		vp := &ViolatedPolicy{
			PolicyID:   policyID,
			PolicyName: p.Name,
			Severity:   p.Severity,
			Action:     p.Action,
			Violations: violations,
		}
		result.ViolatedPolicies = append(result.ViolatedPolicies, vp)

		if p.Severity == SeverityCritical {
			result.HasCritical = true
		}
	}

	sort.Slice(result.ViolatedPolicies, func(i, j int) bool {
		si := severityOrder(result.ViolatedPolicies[i].Severity)
		sj := severityOrder(result.ViolatedPolicies[j].Severity)
		if si != sj {
			return si < sj
		}
		return result.ViolatedPolicies[i].PolicyID < result.ViolatedPolicies[j].PolicyID
	})

	return result, newCache
}

func EvaluatePolicies(report *models.DriftReport, policies []*Policy) *ComplianceResult {
	result, _ := EvaluatePoliciesWithCache(report, policies, nil)
	return result
}

func GroupBySeverity(vps []*ViolatedPolicy) map[Severity][]*ViolatedPolicy {
	grouped := make(map[Severity][]*ViolatedPolicy)
	for _, vp := range vps {
		grouped[vp.Severity] = append(grouped[vp.Severity], vp)
	}
	return grouped
}

func HasBlockAction(vps []*ViolatedPolicy) bool {
	for _, vp := range vps {
		if vp.Action == ActionBlock && vp.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

func SeverityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "\033[31m"
	case SeverityWarning:
		return "\033[33m"
	default:
		return "\033[36m"
	}
}

func SeverityLabel(s Severity) string {
	return strings.ToUpper(string(s))
}
