package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tf-drift/tf-drift/internal/engine"
	"github.com/tf-drift/tf-drift/internal/models"
	multienv "github.com/tf-drift/tf-drift/internal/multi_env"
	"github.com/tf-drift/tf-drift/internal/parsers/config"
	"github.com/tf-drift/tf-drift/internal/remediation"
	"github.com/tf-drift/tf-drift/internal/reporters"
)

const baselineDir = ".tfdrift"

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "detect":
		cmdDetect(args)
	case "compare":
		cmdCompare(args)
	case "baseline":
		cmdBaseline(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Terraform Drift Detection CLI

Usage:
  tf-drift <command> [options]

Commands:
  detect    Detect drift between state and config files
  compare   Compare drift across multiple environments
  baseline  Save current drift state as baseline
  help      Show this help message

Use "tf-drift <command> -h" for more information about a command.`)
}

func cmdDetect(args []string) {
	fs := flag.NewFlagSet("detect", flag.ExitOnError)
	stateFile := fs.String("state-file", "", "Path to terraform.tfstate file")
	configDir := fs.String("config-dir", "", "Path to Terraform config directory")
	workspace := fs.String("workspace", "", "Target workspace name")
	format := fs.String("format", "terminal", "Output format (terminal/json/markdown/html)")
	output := fs.String("output", "", "Output file path (default: stdout)")
	var ignore stringSliceFlag
	fs.Var(&ignore, "ignore", "Ignore rules (resource_type or resource_type.name or resource_type.name.attr)")
	exitCodeFlag := fs.String("exit-code", "", "Exit code mode for CI (any/high/medium)")
	baselineSave := fs.Bool("baseline", false, "Save current results as baseline")
	baselineCompare := fs.String("baseline-compare", "", "Compare against a baseline file (incremental mode)")
	noConfig := fs.Bool("no-config", false, "Ignore .tfdrift.yaml config file")
	fs.Parse(args)

	if *stateFile == "" && *configDir == "" && *noConfig == false {
		cwd, _ := os.Getwd()
		configPath := config.FindDriftConfig(cwd)
		if configPath != "" {
			cfg, _ := config.ParseDriftConfig(configPath)
			if *stateFile == "" && cfg.StateFile != "" {
				*stateFile = cfg.StateFile
			}
			if *configDir == "" && cfg.ConfigDir != "" {
				*configDir = cfg.ConfigDir
			}
			if *workspace == "" && cfg.Workspace != "" {
				*workspace = cfg.Workspace
			}
			if *format == "terminal" && cfg.DefaultFormat != "" {
				*format = cfg.DefaultFormat
			}
			if *exitCodeFlag == "" && cfg.ExitCodeThreshold != "" {
				*exitCodeFlag = cfg.ExitCodeThreshold
			}
		}
	}

	if *stateFile == "" {
		*stateFile = "terraform.tfstate"
	}
	if *configDir == "" {
		*configDir = "."
	}

	var cfg *models.DriftConfig
	if !*noConfig {
		configPath := config.FindDriftConfig(*configDir)
		if configPath != "" {
			parsed, err := config.ParseDriftConfig(configPath)
			if err == nil {
				cfg = parsed
			}
		}
	}
	if cfg == nil {
		cfg = models.NewDriftConfig()
	}

	ignoreRules := make([]*models.IgnoreRule, len(cfg.IgnoreRules))
	copy(ignoreRules, cfg.IgnoreRules)
	for _, ig := range ignore {
		ignoreRules = append(ignoreRules, models.ParseIgnoreRule(ig))
	}

	var baselineDrifts map[string]bool
	if *baselineCompare != "" {
		var err error
		baselineDrifts, err = engine.LoadBaseline(*baselineCompare)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load baseline: %v\n", err)
			baselineDrifts = make(map[string]bool)
		}
	}

	report, depGraph, err := engine.RunDetection(*stateFile, *configDir, *workspace, ignoreRules, baselineDrifts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	engine.AnalyzeImpact(report.Results, depGraph)

	stateMap := make(map[string]*models.TfResource)
	stateResources := report.Results
	for _, res := range stateResources {
		stateMap[res.ResourceAddr] = &models.TfResource{
			Address:      res.ResourceAddr,
			ResourceType: "",
			ResourceName: "",
		}
	}

	remediation.GenerateRemediations(report.Results, stateMap)

	report.ComputeSummary()
	report.SortResults()

	if *baselineSave {
		baselinePath := filepath.Join(baselineDir, "baseline.json")
		if err := os.MkdirAll(baselineDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create baseline dir: %v\n", err)
		} else {
			engine.SaveBaseline(report, baselinePath)
			fmt.Fprintf(os.Stderr, "Baseline saved to %s\n", baselinePath)
		}
	}

	var content string
	var formatErr error

	switch *format {
	case "json":
		content, formatErr = reporters.FormatJSON(report)
	case "markdown":
		content = reporters.FormatMarkdown(report)
	case "html":
		content = reporters.FormatHTML(report)
	default:
		content = reporters.FormatTerminal(report)
	}

	if formatErr != nil {
		fmt.Fprintf(os.Stderr, "Error formatting: %v\n", formatErr)
		os.Exit(1)
	}

	writeOutput(content, *output)

	threshold := *exitCodeFlag
	if threshold == "" {
		threshold = cfg.ExitCodeThreshold
	}
	if threshold == "" {
		threshold = "any"
	}

	ec := getExitCode(report, threshold)
	if ec != 0 {
		os.Exit(ec)
	}
}

func cmdCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	var envStates stringSliceFlag
	fs.Var(&envStates, "env-states", "Environment state files (name=path format)")
	workspace := fs.String("workspace", "", "Workspace name")
	format := fs.String("format", "terminal", "Output format (terminal/json/markdown/html)")
	fs.Parse(args)

	if len(envStates) < 2 {
		fmt.Fprintln(os.Stderr, "Error: At least two state files required for comparison")
		fs.Usage()
		os.Exit(1)
	}

	stateMap := make(map[string]string)
	for _, mapping := range envStates {
		if strings.Contains(mapping, "=") {
			parts := strings.SplitN(mapping, "=", 2)
			stateMap[parts[0]] = parts[1]
		} else {
			stateMap[fmt.Sprintf("env%d", len(stateMap)+1)] = mapping
		}
	}

	envNames := make([]string, 0, len(stateMap))
	for name := range stateMap {
		envNames = append(envNames, name)
	}
	sort.Strings(envNames)

	diffs, err := multienv.CompareEnvironments(stateMap, *workspace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	matrix := multienv.FormatDiffMatrix(diffs, envNames)

	switch *format {
	case "json":
		b, err := json.MarshalIndent(matrix, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(b))
	case "markdown":
		printEnvMarkdown(matrix, envNames)
	case "html":
		printEnvHTML(matrix, envNames)
	default:
		printEnvTerminal(matrix, envNames)
	}
}

func cmdBaseline(args []string) {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	stateFile := fs.String("state-file", "terraform.tfstate", "Path to terraform.tfstate file")
	configDir := fs.String("config-dir", ".", "Path to Terraform config directory")
	baselinePath := fs.String("baseline-path", filepath.Join(baselineDir, "baseline.json"), "Path to save baseline file")
	fs.Parse(args)

	report, _, err := engine.RunDetection(*stateFile, *configDir, "", nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*baselinePath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
		os.Exit(1)
	}

	if err := engine.SaveBaseline(report, *baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving baseline: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Baseline saved to %s (%d drifts recorded)\n", *baselinePath, report.TotalDrifts)
}

func getExitCode(report *models.DriftReport, threshold string) int {
	if report.TotalDrifts == 0 {
		return 0
	}
	switch threshold {
	case "any":
		return 1
	case "high":
		if report.HighRiskCount > 0 {
			return 2
		}
		return 0
	case "medium":
		if report.HighRiskCount > 0 || report.MediumRiskCount > 0 {
			return 2
		}
		return 0
	default:
		return 0
	}
}

func writeOutput(content, outputFile string) {
	if outputFile != "" {
		if dir := filepath.Dir(outputFile); dir != "." {
			os.MkdirAll(dir, 0755)
		}
		if err := os.WriteFile(outputFile, []byte(content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(content)
	}
}

func printEnvTerminal(matrix []map[string]interface{}, envNames []string) {
	sort.Strings(envNames)

	colWidths := make(map[string]int)
	colWidths["resource"] = 20
	colWidths["attribute"] = 20
	for _, env := range envNames {
		colWidths[env] = 15
	}
	for _, row := range matrix {
		for _, col := range append([]string{"resource", "attribute"}, envNames...) {
			w := len(fmt.Sprintf("%v", row[col]))
			if w > colWidths[col] {
				colWidths[col] = w
			}
		}
	}

	fmt.Println("\nEnvironment Comparison")
	fmt.Println(strings.Repeat("=", 80))
	header := fmt.Sprintf("%-*s  %-*s  ", colWidths["resource"], "Resource", colWidths["attribute"], "Attribute")
	for _, env := range envNames {
		header += fmt.Sprintf("%-*s  ", colWidths[env], env)
	}
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", 80))

	for _, row := range matrix {
		line := fmt.Sprintf("%-*s  %-*s  ", colWidths["resource"], row["resource"], colWidths["attribute"], row["attribute"])
		for _, env := range envNames {
			line += fmt.Sprintf("%-*v  ", colWidths[env], row[env])
		}
		if isProd, ok := row["is_production_unique"].(bool); ok && isProd {
			line += "  ⚠ PROD UNIQUE"
		}
		fmt.Println(line)
	}
	fmt.Println()
}

func printEnvMarkdown(matrix []map[string]interface{}, envNames []string) {
	sort.Strings(envNames)
	fmt.Println("# Environment Comparison\n")
	header := "| Resource | Attribute | " + strings.Join(envNames, " | ") + " | Note |"
	sep := "|" + strings.Repeat("---|", len(envNames)+3)
	fmt.Println(header)
	fmt.Println(sep)
	for _, row := range matrix {
		vals := make([]string, len(envNames))
		for i, env := range envNames {
			vals[i] = fmt.Sprintf("%v", row[env])
		}
		note := ""
		if isProd, ok := row["is_production_unique"].(bool); ok && isProd {
			note = "⚠️ PROD UNIQUE"
		}
		fmt.Printf("| %s | %s | %s | %s |\n",
			row["resource"], row["attribute"], strings.Join(vals, " | "), note)
	}
}

func printEnvHTML(matrix []map[string]interface{}, envNames []string) {
	sort.Strings(envNames)
	fmt.Printf(`<table border="1" cellpadding="6"><tr><th>Resource</th><th>Attribute</th>`)
	for _, env := range envNames {
		fmt.Printf("<th>%s</th>", env)
	}
	fmt.Printf("<th>Note</th></tr>")
	for _, row := range matrix {
		fmt.Printf("<tr><td>%v</td><td>%v</td>", row["resource"], row["attribute"])
		for _, env := range envNames {
			fmt.Printf("<td>%v</td>", row[env])
		}
		note := ""
		if isProd, ok := row["is_production_unique"].(bool); ok && isProd {
			note = "⚠ PROD UNIQUE"
		}
		fmt.Printf("<td>%s</td></tr>", note)
	}
	fmt.Println("</table>")
}
