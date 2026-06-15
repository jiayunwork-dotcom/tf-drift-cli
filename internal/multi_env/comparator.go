package multienv

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
	"github.com/tf-drift/tf-drift/internal/parsers/tfstate"
)

func CompareEnvironments(stateFiles map[string]string, workspace string) ([]map[string]interface{}, error) {
	envResources := make(map[string]map[string]*models.TfResource)

	for envName, filePath := range stateFiles {
		resources, _, err := tfstate.ParseFile(filePath, workspace)
		if err != nil {
			return nil, err
		}
		envResources[envName] = resources
	}

	allResourceKeys := make(map[string]bool)
	for _, resources := range envResources {
		for _, res := range resources {
			normalized := res.ResourceType + "." + res.ResourceName
			allResourceKeys[normalized] = true
		}
	}

	envNames := make([]string, 0, len(stateFiles))
	for name := range stateFiles {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	prodName := ""
	for _, name := range envNames {
		if name == "prod" || name == "production" || name == "prd" {
			prodName = name
			break
		}
	}

	diffs := []map[string]interface{}{}

	for resKey := range allResourceKeys {
		envAttrs := make(map[string]map[string]interface{})
		for envName, resources := range envResources {
			for _, res := range resources {
				normalized := res.ResourceType + "." + res.ResourceName
				if normalized == resKey {
					envAttrs[envName] = res.Attributes
					break
				}
			}
		}

		if len(envAttrs) < 2 {
			continue
		}

		allAttrKeys := make(map[string]bool)
		for _, attrs := range envAttrs {
			expanded := models.FlattenStateAttributes(attrs)
			for k := range expanded {
				allAttrKeys[k] = true
			}
		}

		for attrKey := range allAttrKeys {
			if strings.HasPrefix(attrKey, "_") || strings.HasPrefix(attrKey, "terraform_") {
				continue
			}

			values := make(map[string]interface{})
			for envName, attrs := range envAttrs {
				expanded := models.FlattenStateAttributes(attrs)
				if v, ok := expanded[attrKey]; ok {
					values[envName] = v
				}
			}

			uniqueValues := make(map[string]bool)
			for _, v := range values {
				uniqueValues[fmt.Sprintf("%v", v)] = true
			}

			if len(uniqueValues) <= 1 {
				continue
			}

			isProdUnique := false
			if prodName != "" {
				if prodVal, ok := values[prodName]; ok {
					prodStr := fmt.Sprintf("%v", prodVal)
					nonProdVals := make(map[string]bool)
					for envName, val := range values {
						if envName != prodName {
							nonProdVals[fmt.Sprintf("%v", val)] = true
						}
					}
					if len(nonProdVals) == 1 {
						for nonProdVal := range nonProdVals {
							if prodStr != nonProdVal {
								isProdUnique = true
							}
						}
					}
				}
			}

			diff := map[string]interface{}{
				"resource":             resKey,
				"attribute":            attrKey,
				"values":               values,
				"is_production_unique": isProdUnique,
			}
			diffs = append(diffs, diff)
		}
	}

	sort.Slice(diffs, func(i, j int) bool {
		ri := diffs[i]["resource"].(string)
		rj := diffs[j]["resource"].(string)
		if ri != rj {
			return ri < rj
		}
		ai := diffs[i]["attribute"].(string)
		aj := diffs[j]["attribute"].(string)
		return ai < aj
	})

	return diffs, nil
}

func FormatDiffMatrix(diffs []map[string]interface{}, envNames []string) []map[string]interface{} {
	matrix := []map[string]interface{}{}

	sort.Strings(envNames)

	for _, diff := range diffs {
		row := map[string]interface{}{
			"resource":               diff["resource"],
			"attribute":              diff["attribute"],
			"is_production_unique":   diff["is_production_unique"],
		}
		values := diff["values"].(map[string]interface{})
		for _, envName := range envNames {
			if v, ok := values[envName]; ok {
				row[envName] = v
			} else {
				row[envName] = "N/A"
			}
		}
		matrix = append(matrix, row)
	}

	return matrix
}
