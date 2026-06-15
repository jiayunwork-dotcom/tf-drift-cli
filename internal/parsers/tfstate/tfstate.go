package tfstate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
)

const (
	SensitiveMask         = "[SENSITIVE]"
	LargeFileSizeThreshold = 50 * 1024 * 1024
	LargeResourceCount    = 500
)

var (
	knownProviderPrefixes = []string{
		"aws_", "azurerm_", "google_", "oci_", "alicloud_", "huaweicloud_",
		"vsphere_", "openstack_", "helm_", "kubernetes_", "k8s_",
		"docker_", "null_", "random_", "local_", "tls_", "vault_",
	}
)

type TFState struct {
	Version          int               `json:"version"`
	TerraformVersion string            `json:"terraform_version"`
	Serial           int               `json:"serial"`
	Lineage          string            `json:"lineage"`
	Outputs          map[string]interface{} `json:"outputs"`
	Resources        []StateResource   `json:"resources"`
}

type StateResource struct {
	Mode      string          `json:"mode"`
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	Provider  string          `json:"provider"`
	Module    string          `json:"module"`
	Each      string          `json:"each"`
	Instances []StateInstance `json:"instances"`
}

type StateInstance struct {
	IndexKey          interface{}            `json:"index_key"`
	SchemaVersion     int                    `json:"schema_version"`
	Attributes        map[string]interface{} `json:"attributes"`
	AttributesFlat    map[string]interface{} `json:"attributes_flat"`
	SensitiveAttrs    []interface{}          `json:"sensitive_attributes"`
	Dependencies      []string               `json:"dependencies"`
	DependsOn         []string               `json:"depends_on"`
}

func ParseFile(filePath, workspace string) (map[string]*models.TfResource, *models.DependencyGraph, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("state file not found: %s", filePath)
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, err
	}

	if info.Size() > LargeFileSizeThreshold {
		return parseLargeFile(filePath, workspace)
	}

	return parseNormalFile(filePath, workspace)
}

func parseNormalFile(filePath, workspace string) (map[string]*models.TfResource, *models.DependencyGraph, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	return parseFromReader(f, workspace)
}

func parseLargeFile(filePath, workspace string) (map[string]*models.TfResource, *models.DependencyGraph, error) {
	return parseNormalFile(filePath, workspace)
}

func parseFromReader(r io.Reader, workspace string) (map[string]*models.TfResource, *models.DependencyGraph, error) {
	var state TFState
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&state); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}

	resources := make(map[string]*models.TfResource)
	graph := models.NewDependencyGraph()

	for _, res := range state.Resources {
		if res.Mode == "data" {
			continue
		}

		modulePath := res.Module
		if strings.HasPrefix(modulePath, "module.") {
			modulePath = modulePath[len("module."):]
		}

		for i, inst := range res.Instances {
			var instanceKey interface{}
			var indexStr string

			if inst.IndexKey != nil {
				instanceKey = inst.IndexKey
				switch k := inst.IndexKey.(type) {
				case float64:
					indexStr = fmt.Sprintf("%d", int(k))
				case string:
					indexStr = fmt.Sprintf("%q", k)
				default:
					indexStr = fmt.Sprintf("%v", k)
				}
			} else if len(res.Instances) > 1 {
				instanceKey = float64(i)
				indexStr = fmt.Sprintf("%d", i)
			}

			baseAddr := res.Type + "." + res.Name
			if modulePath != "" {
				baseAddr = "module." + modulePath + "." + baseAddr
			}

			fullAddr := baseAddr
			if indexStr != "" {
				fullAddr += "[" + indexStr + "]"
			}

			tfRes := parseInstance(fullAddr, res, modulePath, instanceKey, indexStr, inst)
			resources[fullAddr] = tfRes
			graph.AddResource(tfRes)
		}
	}

	graph.BuildFromReferences(resources)
	return resources, graph, nil
}

func parseInstance(
	addr string,
	res StateResource,
	modulePath string,
	instanceKey interface{},
	indexStr string,
	inst StateInstance,
) *models.TfResource {
	attributes := inst.Attributes
	if attributes == nil {
		attributes = make(map[string]interface{})
	}

	sensitiveKeys := extractSensitiveKeys(inst.SensitiveAttrs, attributes)
	sensitiveKeys = mergeSets(sensitiveKeys, detectSensitiveKeys(attributes))

	maskedAttrs := maskSensitive(attributes, sensitiveKeys)

	dependsOn := inst.Dependencies
	if len(dependsOn) == 0 {
		dependsOn = inst.DependsOn
	}

	references := extractReferences(maskedAttrs)

	providerKey := res.Provider

	createTime := findFirst(maskedAttrs, "create_time", "created_at", "creation_timestamp")
	resourceID := findFirst(maskedAttrs, "id")

	isForEach := false
	forEachKey := ""
	isCount := false

	switch instanceKey.(type) {
	case string:
		isForEach = true
		if k, ok := instanceKey.(string); ok {
			forEachKey = k
		}
	case float64:
		isCount = true
	}

	isUnknownProvider := true
	for _, prefix := range knownProviderPrefixes {
		if strings.HasPrefix(res.Type, prefix) {
			isUnknownProvider = false
			break
		}
	}

	return &models.TfResource{
		Address:           addr,
		ResourceType:      res.Type,
		ResourceName:      res.Name,
		Provider:          providerKey,
		ModulePath:        modulePath,
		Index:             instanceKey,
		IndexStr:          indexStr,
		Attributes:        maskedAttrs,
		SensitiveKeys:     sensitiveKeys,
		DependsOn:         dependsOn,
		References:        references,
		CreateTime:        createTime,
		ResourceID:        resourceID,
		IsForEach:         isForEach,
		IsCount:           isCount,
		ForEachKey:        forEachKey,
		ComputedKeys:      make(map[string]bool),
		ProviderName:      providerKey,
		IsUnknownProvider: isUnknownProvider,
	}
}

func extractSensitiveKeys(sensitive []interface{}, attributes map[string]interface{}) map[string]bool {
	result := make(map[string]bool)
	for _, item := range sensitive {
		switch s := item.(type) {
		case string:
			if strings.HasPrefix(s, "$.") {
				result[s[2:]] = true
			} else {
				result[s] = true
			}
		}
	}
	return result
}

func detectSensitiveKeys(attrs map[string]interface{}) map[string]bool {
	result := make(map[string]bool)
	detectSensitiveRecursive(attrs, "", result)
	return result
}

func detectSensitiveRecursive(attrs map[string]interface{}, prefix string, result map[string]bool) {
	for key, value := range attrs {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		if key == "sensitive" {
			if b, ok := value.(bool); ok && b {
				if prefix != "" {
					parts := strings.Split(prefix, ".")
					parentKey := parts[len(parts)-1]
					if parentKey != "" {
						result[parentKey] = true
					}
				}
			}
		}
		if nested, ok := value.(map[string]interface{}); ok {
			detectSensitiveRecursive(nested, fullKey, result)
		}
		if arr, ok := value.([]interface{}); ok {
			for i, item := range arr {
				if nested, ok := item.(map[string]interface{}); ok {
					detectSensitiveRecursive(nested, fmt.Sprintf("%s.%d", fullKey, i), result)
				}
			}
		}
	}
}

func maskSensitive(attrs map[string]interface{}, sensitiveKeys map[string]bool) map[string]interface{} {
	return maskSensitiveRecursive(attrs, sensitiveKeys, "")
}

func maskSensitiveRecursive(attrs map[string]interface{}, sensitiveKeys map[string]bool, prefix string) map[string]interface{} {
	masked := make(map[string]interface{})
	for key, value := range attrs {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		if sensitiveKeys[fullKey] || sensitiveKeys[key] {
			masked[key] = SensitiveMask
			continue
		}
		if nested, ok := value.(map[string]interface{}); ok {
			masked[key] = maskSensitiveRecursive(nested, sensitiveKeys, fullKey)
		} else if arr, ok := value.([]interface{}); ok {
			newArr := make([]interface{}, len(arr))
			for i, item := range arr {
				if nested, ok := item.(map[string]interface{}); ok {
					newArr[i] = maskSensitiveRecursive(nested, sensitiveKeys, fmt.Sprintf("%s.%d", fullKey, i))
				} else {
					newArr[i] = item
				}
			}
			masked[key] = newArr
		} else {
			masked[key] = value
		}
	}
	return masked
}

var (
	refPattern1 = regexp.MustCompile(`\$\{(.*?)\}`)
	refPattern2 = regexp.MustCompile(`\b(var\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
	refPattern3 = regexp.MustCompile(`\b(local\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
	refPattern4 = regexp.MustCompile(`\b(data\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
	refPattern5 = regexp.MustCompile(`\b(module\.[a-zA-Z_][a-zA-Z0-9_.]*)\b`)
)

func extractReferences(attrs map[string]interface{}) []models.ResourceRef {
	refs := []models.ResourceRef{}
	seen := make(map[string]bool)

	var scan func(interface{})
	scan = func(val interface{}) {
		switch v := val.(type) {
		case string:
			patterns := []*regexp.Regexp{refPattern1, refPattern2, refPattern3, refPattern4, refPattern5}
			for _, pat := range patterns {
				matches := pat.FindAllStringSubmatch(v, -1)
				for _, match := range matches {
					refStr := match[0]
					if pat == refPattern1 {
						refStr = match[1]
					}
					refStr = strings.TrimSpace(refStr)
					if refStr != "" && !seen[refStr] {
						seen[refStr] = true
						refs = append(refs, parseReference(refStr))
					}
				}
			}
		case []interface{}:
			for _, item := range v {
				scan(item)
			}
		case map[string]interface{}:
			for _, item := range v {
				scan(item)
			}
		}
	}

	for _, v := range attrs {
		scan(v)
	}

	return refs
}

func parseReference(refStr string) models.ResourceRef {
	parts := strings.Split(refStr, ".")
	modulePath := ""
	idx := 0

	if len(parts) >= 2 && parts[0] == "module" {
		modulePath = parts[1]
		idx = 2
	}

	remaining := parts[idx:]
	refType := "resource"
	var resourceType, resourceName, attribute string

	if len(remaining) >= 1 {
		switch remaining[0] {
		case "var":
			refType = "var"
			if len(remaining) >= 2 {
				resourceName = remaining[1]
			}
		case "local":
			refType = "local"
			if len(remaining) >= 2 {
				resourceName = remaining[1]
			}
		case "data":
			refType = "data"
			resourceType = "data"
			if len(remaining) >= 3 {
				resourceName = remaining[2]
			}
			if len(remaining) > 3 {
				attribute = strings.Join(remaining[3:], ".")
			}
		default:
			if len(remaining) >= 2 {
				resourceType = remaining[0]
				resourceName = remaining[1]
				if len(remaining) > 2 {
					attribute = strings.Join(remaining[2:], ".")
				}
			}
		}
	}

	return models.ResourceRef{
		RefType:      refType,
		ModulePath:   modulePath,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Attribute:    attribute,
		Raw:          refStr,
	}
}

func findFirst(attrs map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := attrs[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func mergeSets(a, b map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for k := range a {
		result[k] = true
	}
	for k := range b {
		result[k] = true
	}
	return result
}

func StreamResources(filePath string) (<-chan *models.TfResource, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("state file not found: %s", filePath)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	out := make(chan *models.TfResource, 10)

	go func() {
		defer f.Close()
		defer close(out)

		var state TFState
		decoder := json.NewDecoder(f)
		if err := decoder.Decode(&state); err != nil {
			return
		}

		for _, res := range state.Resources {
			if res.Mode == "data" {
				continue
			}

			modulePath := res.Module
			if strings.HasPrefix(modulePath, "module.") {
				modulePath = modulePath[len("module."):]
			}

			for i, inst := range res.Instances {
				var instanceKey interface{}
				var indexStr string

				if inst.IndexKey != nil {
					instanceKey = inst.IndexKey
					switch k := inst.IndexKey.(type) {
					case float64:
						indexStr = fmt.Sprintf("%d", int(k))
					case string:
						indexStr = fmt.Sprintf("%q", k)
					default:
						indexStr = fmt.Sprintf("%v", k)
					}
				} else if len(res.Instances) > 1 {
					instanceKey = float64(i)
					indexStr = fmt.Sprintf("%d", i)
				}

				baseAddr := res.Type + "." + res.Name
				if modulePath != "" {
					baseAddr = "module." + modulePath + "." + baseAddr
				}

				fullAddr := baseAddr
				if indexStr != "" {
					fullAddr += "[" + indexStr + "]"
				}

				out <- parseInstance(fullAddr, res, modulePath, instanceKey, indexStr, inst)
			}
		}
	}()

	return out, nil
}
