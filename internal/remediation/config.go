package remediation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type RemediateRule struct {
	Match         string `yaml:"match"`
	Condition     string `yaml:"condition"`
	Timeout       *int   `yaml:"timeout"`
	PostCondition string `yaml:"post_condition"`
}

type RemediateConfig struct {
	Rules         []*RemediateRule `yaml:"rules"`
	DefaultTimeout *int             `yaml:"default_timeout"`
}

func LoadRemediateConfig(path string) (*RemediateConfig, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", absPath, err)
	}

	var cfg RemediateConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", absPath, err)
	}

	return &cfg, nil
}

func FindRemediateConfig(dir string) string {
	candidates := []string{
		".tfdrift-remediate.yaml",
		".tfdrift-remediate.yml",
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}

	for _, candidate := range candidates {
		fullPath := filepath.Join(absDir, candidate)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}

	return ""
}

func (cfg *RemediateConfig) ApplyToAction(action *RemediationAction, globalTimeout int) {
	resourceType := extractResourceType(action.ResourceAddr)

	if cfg != nil {
		var exactMatch *RemediateRule
		var globMatch *RemediateRule
		var typeGlobMatch *RemediateRule

		for _, rule := range cfg.Rules {
			if rule.Match == "" {
				continue
			}

			if strings.Contains(rule.Match, ".") {
				if rule.Match == action.ResourceAddr {
					exactMatch = rule
				} else if ok, _ := filepath.Match(rule.Match, action.ResourceAddr); ok {
					if globMatch == nil {
						globMatch = rule
					}
				}
			} else {
				if ok, _ := filepath.Match(rule.Match, resourceType); ok {
					if typeGlobMatch == nil {
						typeGlobMatch = rule
					}
				}
			}
		}

		var bestMatch *RemediateRule
		if exactMatch != nil {
			bestMatch = exactMatch
		} else if globMatch != nil {
			bestMatch = globMatch
		} else if typeGlobMatch != nil {
			bestMatch = typeGlobMatch
		}

		if bestMatch != nil {
			if bestMatch.Condition != "" && action.Condition == "" {
				action.Condition = bestMatch.Condition
			}
			if bestMatch.Timeout != nil && action.Timeout == 0 {
				action.Timeout = *bestMatch.Timeout
			}
			if bestMatch.PostCondition != "" && action.PostCondition == "" {
				action.PostCondition = bestMatch.PostCondition
			}
		}
	}

	if action.Timeout == 0 {
		if cfg != nil && cfg.DefaultTimeout != nil {
			action.Timeout = *cfg.DefaultTimeout
		} else if globalTimeout > 0 {
			action.Timeout = globalTimeout
		} else {
			action.Timeout = DefaultActionTimeout
		}
	}

	if action.PostCondition == "" && action.ActionType == ActionApply {
		action.PostCondition = fmt.Sprintf("terraform plan -detailed-exitcode -target=%s", action.ResourceAddr)
	}
}
