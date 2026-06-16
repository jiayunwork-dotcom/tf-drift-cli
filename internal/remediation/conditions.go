package remediation

import (
	"fmt"
	"strings"
)

type ConditionVars struct {
	RiskLevel    string
	DriftType    string
	ActionType   string
	ResourceType string
}

func EvaluateCondition(expr string, vars ConditionVars) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true, nil
	}

	return evalOr(expr, vars)
}

func evalOr(expr string, vars ConditionVars) (bool, error) {
	parts := splitTopLevel(expr, "||")
	if len(parts) == 1 {
		return evalAnd(parts[0], vars)
	}

	for _, part := range parts {
		result, err := evalAnd(strings.TrimSpace(part), vars)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}
	return false, nil
}

func evalAnd(expr string, vars ConditionVars) (bool, error) {
	parts := splitTopLevel(expr, "&&")
	if len(parts) == 1 {
		return evalComparison(strings.TrimSpace(parts[0]), vars)
	}

	for _, part := range parts {
		result, err := evalComparison(strings.TrimSpace(part), vars)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}
	return true, nil
}

func evalComparison(expr string, vars ConditionVars) (bool, error) {
	if strings.Contains(expr, "==") {
		parts := strings.SplitN(expr, "==", 2)
		if len(parts) != 2 {
			return false, fmt.Errorf("invalid comparison: %s", expr)
		}
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		leftVal := getVarValue(left, vars)
		rightVal := getVarValue(right, vars)
		return leftVal == rightVal, nil
	}

	if strings.Contains(expr, "!=") {
		parts := strings.SplitN(expr, "!=", 2)
		if len(parts) != 2 {
			return false, fmt.Errorf("invalid comparison: %s", expr)
		}
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		leftVal := getVarValue(left, vars)
		rightVal := getVarValue(right, vars)
		return leftVal != rightVal, nil
	}

	return false, fmt.Errorf("invalid expression: %s (expected == or !=)", expr)
}

func getVarValue(token string, vars ConditionVars) string {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, "\"")
	token = strings.Trim(token, "'")

	switch token {
	case "risk_level":
		return vars.RiskLevel
	case "drift_type":
		return vars.DriftType
	case "action_type":
		return vars.ActionType
	case "resource_type":
		return vars.ResourceType
	default:
		return token
	}
}

func splitTopLevel(expr string, sep string) []string {
	var parts []string
	depth := 0
	current := ""

	for i := 0; i < len(expr); {
		if expr[i] == '(' {
			depth++
			current += string(expr[i])
			i++
		} else if expr[i] == ')' {
			depth--
			current += string(expr[i])
			i++
		} else if strings.HasPrefix(expr[i:], sep) && depth == 0 {
			parts = append(parts, current)
			current = ""
			i += len(sep)
		} else {
			current += string(expr[i])
			i++
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

func extractResourceType(resourceAddr string) string {
	parts := strings.SplitN(resourceAddr, ".", 3)
	if len(parts) >= 2 {
		if parts[0] == "module" {
			if len(parts) >= 3 {
				rest := parts[2]
				restParts := strings.SplitN(rest, ".", 2)
				if len(restParts) >= 1 {
					return restParts[0]
				}
			}
			return ""
		}
		return parts[0]
	}
	return ""
}
