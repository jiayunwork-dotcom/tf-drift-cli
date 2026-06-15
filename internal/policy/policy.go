package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
	"gopkg.in/yaml.v3"
	"os"
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

type PolicyMatch struct {
	ResourceTypes []string `yaml:"resource_types"`
	Attributes    []string `yaml:"attributes"`
	DriftTypes    []string `yaml:"drift_types"`
}

type Policy struct {
	ID       string      `yaml:"id"`
	Name     string      `yaml:"name"`
	Severity Severity    `yaml:"severity"`
	Match    PolicyMatch `yaml:"match"`
	Action   Action      `yaml:"action"`
}

type PolicyFile struct {
	Policies []*Policy `yaml:"policies"`
}

type Violation struct {
	Policy        *Policy
	ResourceAddr  string
	AttributePath string
	DriftType     models.DriftType
}

type ComplianceResult struct {
	ViolatedPolicies []*ViolatedPolicy
	HasCritical      bool
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

func LoadPolicyFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if err := pf.Validate(); err != nil {
		return nil, err
	}

	return &pf, nil
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

	return nil
}

func (p *Policy) Matches(drift *models.DriftItem, resourceType string) bool {
	if len(p.Match.ResourceTypes) > 0 {
		matched := false
		for _, pattern := range p.Match.ResourceTypes {
			if ok, _ := filepath.Match(pattern, resourceType); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(p.Match.Attributes) > 0 {
		matched := false
		attrPath := drift.AttributePath
		for _, pattern := range p.Match.Attributes {
			if ok, _ := filepath.Match(pattern, attrPath); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(p.Match.DriftTypes) > 0 {
		category := driftTypeToCategory(drift.DriftType)
		matched := false
		for _, dt := range p.Match.DriftTypes {
			if DriftTypeCategory(dt) == category {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func EvaluatePolicies(report *models.DriftReport, policies []*Policy) *ComplianceResult {
	result := &ComplianceResult{
		ViolatedPolicies: []*ViolatedPolicy{},
	}

	policyViolations := make(map[string][]*ViolationItem)
	policyMap := make(map[string]*Policy)

	for _, p := range policies {
		policyMap[p.ID] = p
	}

	for _, res := range report.Results {
		resourceType := res.ResourceType
		for _, drift := range res.Drifts {
			for _, p := range policies {
				if p.Matches(drift, resourceType) {
					item := &ViolationItem{
						ResourceAddr:  res.ResourceAddr,
						AttributePath: drift.AttributePath,
						DriftType:     drift.DriftType,
					}
					policyViolations[p.ID] = append(policyViolations[p.ID], item)
				}
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
