package config

import (
	"bufio"
	"os"
	"strings"

	"github.com/tf-drift/tf-drift/internal/models"
)

func ParseDriftConfig(configPath string) (*models.DriftConfig, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return models.NewDriftConfig(), nil
	}

	file, err := os.Open(configPath)
	if err != nil {
		return models.NewDriftConfig(), err
	}
	defer file.Close()

	config := models.NewDriftConfig()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		// Remove comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimRight(line, " \t")
		if line == "" {
			continue
		}

		trimmed := strings.TrimLeft(line, " \t")
		indent := len(line) - len(trimmed)

		if indent == 0 {
			if strings.Contains(trimmed, ":") {
				parts := strings.SplitN(trimmed, ":", 2)
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, "\"'")
				if value != "" {
					setConfigValue(config, key, value)
				}
			}
		} else if indent == 2 {
			if strings.HasPrefix(trimmed, "- ") {
				// List item
				item := strings.TrimSpace(trimmed[2:])
				item = strings.Trim(item, "\"'")
				if item != "" {
					config.IgnoreRules = append(config.IgnoreRules, models.ParseIgnoreRule(item))
				}
			} else if strings.Contains(trimmed, ":") {
				parts := strings.SplitN(trimmed, ":", 2)
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, "\"'")
				if value != "" {
					setConfigValue(config, key, value)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return models.NewDriftConfig(), err
	}

	return config, nil
}

func setConfigValue(config *models.DriftConfig, key, value string) {
	switch key {
	case "format":
		config.DefaultFormat = value
	case "exit_code_threshold":
		config.ExitCodeThreshold = value
	case "state_file":
		config.StateFile = value
	case "config_dir":
		config.ConfigDir = value
	case "workspace":
		config.Workspace = value
	}
}

func FindDriftConfig(startDir string) string {
	candidates := []string{".tfdrift.yaml", ".tfdrift.yml", "tfdrift.yaml", "tfdrift.yml"}
	current := startDir

	for {
		for _, name := range candidates {
			path := current + string(os.PathSeparator) + name
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				return path
			}
		}
		parent := parentDir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return ""
}

func parentDir(path string) string {
	idx := strings.LastIndex(path, string(os.PathSeparator))
	if idx <= 0 {
		return path
	}
	return path[:idx]
}
