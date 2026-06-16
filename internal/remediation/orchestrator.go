package remediation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tf-drift/tf-drift/internal/models"
)

type ActionType string

const (
	ActionApply  ActionType = "apply"
	ActionImport ActionType = "import"
	ActionRemove ActionType = "remove"
	ActionIgnore ActionType = "ignore"
)

type ActionStatus string

const (
	StatusPending    ActionStatus = "pending"
	StatusRunning    ActionStatus = "running"
	StatusSuccess    ActionStatus = "success"
	StatusFailed     ActionStatus = "failed"
	StatusRolledBack ActionStatus = "rolled_back"
)

type RemediationAction struct {
	ID             string       `json:"id"`
	ResourceAddr   string       `json:"resource_addr"`
	ActionType     ActionType   `json:"action_type"`
	Command        string       `json:"command"`
	RollbackCmd    string       `json:"rollback_command"`
	DependsOn      []string     `json:"depends_on"`
	Status         ActionStatus `json:"status"`
	StartedAt      string       `json:"started_at,omitempty"`
	FinishedAt     string       `json:"finished_at,omitempty"`
	DurationMs     int64        `json:"duration_ms,omitempty"`
	Error          string       `json:"error,omitempty"`
	RiskLevel      string       `json:"risk_level"`
	DriftType      string       `json:"drift_type"`
}

type ActionLayer struct {
	Level   int                 `json:"level"`
	Actions []*RemediationAction `json:"actions"`
}

type ExecutionPlan struct {
	Layers              []*ActionLayer       `json:"layers"`
	CriticalPath        []string             `json:"critical_path"`
	EstimatedParallelism float64             `json:"estimated_parallelism"`
	TotalActions        int                  `json:"total_actions"`
	TotalLayers         int                  `json:"total_layers"`
}

type RemediateState struct {
	Actions  []*RemediationAction `json:"actions"`
	Plan     *ExecutionPlan       `json:"plan"`
	StartedAt string              `json:"started_at"`
	UpdatedAt string              `json:"updated_at"`
	Finished  bool                `json:"finished"`
}

type Orchestrator struct {
	actions     []*RemediationAction
	actionMap   map[string]*RemediationAction
	plan        *ExecutionPlan
	depGraph    *models.DependencyGraph
	stateFile   string
	concurrency int
	noRollback  bool
	dryRun      bool
	mu          sync.Mutex
}

func computeActionID(resourceAddr, driftType, attributePath string) string {
	h := sha256.New()
	h.Write([]byte(resourceAddr + "::" + driftType + "::" + attributePath))
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func determineActionType(driftType models.DriftType) ActionType {
	switch driftType {
	case models.DriftResourceMissing:
		return ActionImport
	case models.DriftOrphanResource:
		return ActionRemove
	default:
		return ActionApply
	}
}

func determineCommand(actionType ActionType, resourceAddr string) string {
	switch actionType {
	case ActionApply:
		return "terraform apply -target=" + resourceAddr
	case ActionImport:
		return "terraform import " + resourceAddr + " <RESOURCE_ID>"
	case ActionRemove:
		return "terraform state rm " + resourceAddr
	default:
		return "# no-op"
	}
}

func determineRollbackCommand(actionType ActionType, resourceAddr string) string {
	switch actionType {
	case ActionApply:
		return "terraform plan -destroy -target=" + resourceAddr
	case ActionImport:
		return "terraform state rm " + resourceAddr
	case ActionRemove:
		return ""
	default:
		return ""
	}
}

func NewOrchestrator(report *models.DriftReport, depGraph *models.DependencyGraph, opts ...OrchestratorOption) *Orchestrator {
	o := &Orchestrator{
		depGraph:    depGraph,
		actionMap:   make(map[string]*RemediationAction),
		stateFile:   ".tfdrift-remediate-state.json",
		concurrency: 4,
	}

	for _, opt := range opts {
		opt(o)
	}

	o.buildActions(report)
	o.buildDAG()
	return o
}

type OrchestratorOption func(*Orchestrator)

func WithConcurrency(c int) OrchestratorOption {
	return func(o *Orchestrator) {
		if c > 0 {
			o.concurrency = c
		}
	}
}

func WithNoRollback(noRollback bool) OrchestratorOption {
	return func(o *Orchestrator) {
		o.noRollback = noRollback
	}
}

func WithDryRun(dryRun bool) OrchestratorOption {
	return func(o *Orchestrator) {
		o.dryRun = dryRun
	}
}

func WithStateFile(path string) OrchestratorOption {
	return func(o *Orchestrator) {
		o.stateFile = path
	}
}

func (o *Orchestrator) buildActions(report *models.DriftReport) {
	resourceActions := make(map[string]*RemediationAction)

	for _, result := range report.Results {
		if len(result.Drifts) == 0 {
			continue
		}

		resourceAddr := result.ResourceAddr
		var primaryDrift *models.DriftItem
		for _, d := range result.Drifts {
			if d.DriftType == models.DriftResourceMissing || d.DriftType == models.DriftOrphanResource {
				primaryDrift = d
				break
			}
		}
		if primaryDrift == nil {
			primaryDrift = result.Drifts[0]
		}

		actionType := determineActionType(primaryDrift.DriftType)
		cmd := determineCommand(actionType, resourceAddr)
		rollbackCmd := determineRollbackCommand(actionType, resourceAddr)

		id := computeActionID(resourceAddr, string(primaryDrift.DriftType), primaryDrift.AttributePath)

		var dependsOn []string
		if o.depGraph != nil {
			upstream := o.depGraph.GetUpstream(resourceAddr)
			for depAddr := range upstream {
				depID := computeActionID(depAddr, "", "*")
				if _, exists := resourceActions[depAddr]; exists {
					dependsOn = append(dependsOn, resourceActions[depAddr].ID)
				} else {
					dependsOn = append(dependsOn, depID)
				}
			}
		}

		action := &RemediationAction{
			ID:           id,
			ResourceAddr: resourceAddr,
			ActionType:   actionType,
			Command:      cmd,
			RollbackCmd:  rollbackCmd,
			DependsOn:    dependsOn,
			Status:       StatusPending,
			RiskLevel:    string(result.MaxRisk),
			DriftType:    string(primaryDrift.DriftType),
		}

		o.actions = append(o.actions, action)
		o.actionMap[id] = action
		resourceActions[resourceAddr] = action
	}

	for _, action := range o.actions {
		var validDeps []string
		for _, depID := range action.DependsOn {
			if _, exists := o.actionMap[depID]; exists {
				validDeps = append(validDeps, depID)
			}
		}
		action.DependsOn = validDeps
	}
}

func (o *Orchestrator) buildDAG() {
	if len(o.actions) == 0 {
		o.plan = &ExecutionPlan{
			Layers:      []*ActionLayer{},
			TotalLayers: 0,
			TotalActions: 0,
		}
		return
	}

	var layers []*ActionLayer
	level := 0
	remaining := make(map[string]bool)
	for _, action := range o.actions {
		remaining[action.ID] = true
	}

	for len(remaining) > 0 {
		var ready []*RemediationAction
		for id := range remaining {
			action := o.actionMap[id]
			depsSatisfied := true
			for _, dep := range action.DependsOn {
				if remaining[dep] {
					depsSatisfied = false
					break
				}
			}
			if depsSatisfied {
				ready = append(ready, action)
			}
		}

		if len(ready) == 0 {
			break
		}

		layer := &ActionLayer{
			Level:   level,
			Actions: ready,
		}
		layers = append(layers, layer)

		for _, action := range ready {
			delete(remaining, action.ID)
		}
		level++
	}

	criticalPath := o.computeCriticalPath(layers)

	var totalActions int
	for _, layer := range layers {
		totalActions += len(layer.Actions)
	}

	estimatedParallelism := 0.0
	if totalActions > 0 && len(layers) > 0 {
		estimatedParallelism = float64(totalActions) / float64(len(layers))
	}

	o.plan = &ExecutionPlan{
		Layers:               layers,
		CriticalPath:         criticalPath,
		EstimatedParallelism: estimatedParallelism,
		TotalActions:         totalActions,
		TotalLayers:          len(layers),
	}
}

func (o *Orchestrator) computeCriticalPath(layers []*ActionLayer) []string {
	if len(layers) == 0 {
		return nil
	}

	longestDist := make(map[string]int)
	pred := make(map[string]string)

	for _, action := range o.actions {
		longestDist[action.ID] = 0
	}

	for _, layer := range layers {
		for _, action := range layer.Actions {
			for _, depID := range action.DependsOn {
				if longestDist[depID]+1 > longestDist[action.ID] {
					longestDist[action.ID] = longestDist[depID] + 1
					pred[action.ID] = depID
				}
			}
		}
	}

	var endNode string
	maxDist := -1
	for id, dist := range longestDist {
		if dist > maxDist {
			maxDist = dist
			endNode = id
		}
	}

	var path []string
	current := endNode
	for current != "" {
		action := o.actionMap[current]
		path = append([]string{action.ResourceAddr}, path...)
		current = pred[current]
	}

	return path
}

func (o *Orchestrator) DetectCycle() ([]string, bool) {
	white, gray, black := 0, 1, 2
	color := make(map[string]int)
	for _, action := range o.actions {
		color[action.ID] = white
	}

	var cycleNodes []string

	var dfs func(id string, path []string) bool
	dfs = func(id string, path []string) bool {
		color[id] = gray
		action := o.actionMap[id]
		currentPath := append(path, action.ResourceAddr)
		for _, dep := range action.DependsOn {
			for i, addr := range currentPath {
				if a, ok := o.actionMap[dep]; ok && addr == a.ResourceAddr {
					cycleNodes = append(currentPath[i:], a.ResourceAddr)
					return true
				}
			}
			if color[dep] == gray {
				if a, ok := o.actionMap[dep]; ok {
					cycleNodes = append(currentPath, a.ResourceAddr)
					return true
				}
			}
			if color[dep] == white {
				if dfs(dep, currentPath) {
					return true
				}
			}
		}
		color[id] = black
		return false
	}

	for _, action := range o.actions {
		if color[action.ID] == white {
			if dfs(action.ID, nil) {
				return cycleNodes, true
			}
		}
	}

	return nil, false
}

func (o *Orchestrator) GetPlan() *ExecutionPlan {
	return o.plan
}

func (o *Orchestrator) FormatPlanJSON() map[string]interface{} {
	plan := o.plan
	layers := make([]map[string]interface{}, len(plan.Layers))
	for i, layer := range plan.Layers {
		actions := make([]map[string]interface{}, len(layer.Actions))
		for j, action := range layer.Actions {
			actions[j] = map[string]interface{}{
				"id":            action.ID,
				"resource_addr": action.ResourceAddr,
				"action_type":   string(action.ActionType),
				"command":       action.Command,
				"depends_on":    action.DependsOn,
				"risk_level":    action.RiskLevel,
				"drift_type":    action.DriftType,
			}
		}
		layers[i] = map[string]interface{}{
			"level":   layer.Level,
			"actions": actions,
		}
	}

	return map[string]interface{}{
		"execution_plan": map[string]interface{}{
			"layers":                layers,
			"critical_path":         plan.CriticalPath,
			"estimated_parallelism": plan.EstimatedParallelism,
			"total_actions":         plan.TotalActions,
			"total_layers":          plan.TotalLayers,
		},
	}
}

func (o *Orchestrator) FormatPlanTerminal() string {
	var sb strings.Builder
	plan := o.plan

	sb.WriteString(fmt.Sprintf("\n\033[1m\033[36m═══ Remediation Execution Plan ═══\033[0m\n\n"))
	sb.WriteString(fmt.Sprintf("  Total Actions: %d\n", plan.TotalActions))
	sb.WriteString(fmt.Sprintf("  Total Layers:  %d\n", plan.TotalLayers))
	sb.WriteString(fmt.Sprintf("  Estimated Parallelism: %.1f\n", plan.EstimatedParallelism))

	if len(plan.CriticalPath) > 0 {
		sb.WriteString(fmt.Sprintf("  Critical Path: %s\n", strings.Join(plan.CriticalPath, " → ")))
	}

	sb.WriteString("\n")

	for _, layer := range plan.Layers {
		sb.WriteString(fmt.Sprintf("\033[1m  Layer %d/%d\033[0m (max concurrency: %d", layer.Level+1, plan.TotalLayers, o.concurrency))
		if len(layer.Actions) < o.concurrency {
			sb.WriteString(fmt.Sprintf(", actual: %d", len(layer.Actions)))
		}
		sb.WriteString(")\n")

		for _, action := range layer.Actions {
			sb.WriteString(fmt.Sprintf("    ┌─ %s%s%s [%s%s%s]\n",
				"\033[1m", action.ResourceAddr, "\033[0m",
				actionTypeColor(action.ActionType), string(action.ActionType), "\033[0m"))
			sb.WriteString(fmt.Sprintf("    │  Command: %s\n", action.Command))
			if len(action.DependsOn) > 0 {
				depAddrs := make([]string, len(action.DependsOn))
				for i, depID := range action.DependsOn {
					if a, ok := o.actionMap[depID]; ok {
						depAddrs[i] = a.ResourceAddr
					} else {
						depAddrs[i] = depID[:8] + "..."
					}
				}
				sb.WriteString(fmt.Sprintf("    │  Depends: %s\n", strings.Join(depAddrs, ", ")))
			}
			sb.WriteString(fmt.Sprintf("    │  Risk:    %s\n", action.RiskLevel))
			sb.WriteString("    └─\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func actionTypeColor(at ActionType) string {
	switch at {
	case ActionApply:
		return "\033[33m"
	case ActionImport:
		return "\033[36m"
	case ActionRemove:
		return "\033[31m"
	case ActionIgnore:
		return "\033[2m"
	default:
		return ""
	}
}

func (o *Orchestrator) loadState() (*RemediateState, bool) {
	data, err := os.ReadFile(o.stateFile)
	if err != nil {
		return nil, false
	}
	var state RemediateState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false
	}
	return &state, true
}

func (o *Orchestrator) saveState() error {
	now := time.Now().Format(time.RFC3339)
	state := &RemediateState{
		Actions:   o.actions,
		Plan:      o.plan,
		StartedAt: now,
		UpdatedAt: now,
	}

	for _, a := range o.actions {
		if a.Status == StatusPending || a.Status == StatusRunning {
			state.Finished = false
			break
		}
		state.Finished = true
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(o.stateFile, data, 0644)
}

func (o *Orchestrator) CheckExistingState() (*RemediateState, bool) {
	state, exists := o.loadState()
	if !exists {
		return nil, false
	}
	if state.Finished {
		return nil, false
	}
	for _, a := range state.Actions {
		if a.Status == StatusPending || a.Status == StatusRunning {
			return state, true
		}
	}
	return nil, false
}

func (o *Orchestrator) ResumeFromState(state *RemediateState) {
	o.actions = state.Actions
	o.actionMap = make(map[string]*RemediationAction)
	for _, a := range o.actions {
		o.actionMap[a.ID] = a
	}
	o.plan = state.Plan
}

func (o *Orchestrator) Execute() error {
	if o.dryRun {
		return nil
	}

	o.saveState()

	var failedActions []*RemediationAction
	var successActions []*RemediationAction

	for _, layer := range o.plan.Layers {
		fmt.Printf("\n\033[1m[Layer %d/%d]\033[0m Executing %d action(s) (concurrency: %d)\n",
			layer.Level+1, o.plan.TotalLayers, len(layer.Actions), o.concurrency)

		results := o.executeLayer(layer)

		layerFailed := false
		for _, r := range results {
			if r.Status == StatusSuccess {
				successActions = append(successActions, r)
			} else if r.Status == StatusFailed {
				failedActions = append(failedActions, r)
				layerFailed = true
			}
		}

		if layerFailed {
			fmt.Printf("\n\033[31m\033[1m✗ Layer %d had failures, skipping remaining layers\033[0m\n", layer.Level+1)
			break
		}
	}

	if len(failedActions) > 0 && !o.noRollback {
		fmt.Printf("\n\033[33m\033[1m⚠ Entering rollback phase (%d actions to roll back)\033[0m\n", len(successActions))
		o.executeRollback(successActions)
	}

	if len(failedActions) > 0 {
		fmt.Printf("\n\033[31m\033[1m✗ Remediation completed with %d failure(s)\033[0m\n", len(failedActions))
		for _, a := range failedActions {
			fmt.Printf("  - %s [%s]: %s\n", a.ResourceAddr, a.ActionType, a.Error)
		}
		return fmt.Errorf("remediation had %d failure(s)", len(failedActions))
	}

	fmt.Printf("\n\033[32m\033[1m✓ All remediation actions completed successfully\033[0m\n")
	return nil
}

func (o *Orchestrator) executeLayer(layer *ActionLayer) []*RemediationAction {
	results := make([]*RemediationAction, len(layer.Actions))
	var wg sync.WaitGroup
	sem := make(chan struct{}, o.concurrency)

	for i, action := range layer.Actions {
		wg.Add(1)
		go func(idx int, a *RemediationAction) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			o.mu.Lock()
			a.Status = StatusRunning
			a.StartedAt = time.Now().Format(time.RFC3339)
			o.mu.Unlock()

			o.saveState()

			fmt.Printf("  \033[36m[Layer %d/%d]\033[0m 执行: %s (%s)\n",
				layer.Level+1, o.plan.TotalLayers, a.ResourceAddr, string(a.ActionType))

			start := time.Now()
			err := o.runCommand(a.Command)
			elapsed := time.Since(start)

			o.mu.Lock()
			a.FinishedAt = time.Now().Format(time.RFC3339)
			a.DurationMs = elapsed.Milliseconds()
			if err != nil {
				a.Status = StatusFailed
				a.Error = err.Error()
				fmt.Printf("  \033[31m  ✗ %s [%s] failed (%dms): %s\033[0m\n",
					a.ResourceAddr, a.ActionType, a.DurationMs, err.Error())
			} else {
				a.Status = StatusSuccess
				fmt.Printf("  \033[32m  ✓ %s [%s] success (%dms)\033[0m\n",
					a.ResourceAddr, a.ActionType, a.DurationMs)
			}
			o.mu.Unlock()

			o.saveState()
			results[idx] = a
		}(i, action)
	}

	wg.Wait()
	return results
}

func (o *Orchestrator) runCommand(cmdStr string) error {
	if strings.HasPrefix(cmdStr, "#") || strings.HasPrefix(cmdStr, "<") {
		return nil
	}

	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

func (o *Orchestrator) executeRollback(successActions []*RemediationAction) {
	for i := len(successActions) - 1; i >= 0; i-- {
		action := successActions[i]
		if action.RollbackCmd == "" {
			fmt.Printf("  \033[2m  ⊘ %s [%s] no rollback command\033[0m\n", action.ResourceAddr, action.ActionType)
			continue
		}

		fmt.Printf("  \033[33m  ↩ Rolling back: %s [%s]\033[0m\n", action.ResourceAddr, action.ActionType)
		err := o.runCommand(action.RollbackCmd)

		o.mu.Lock()
		if err != nil {
			fmt.Printf("  \033[31m  ⚠ Rollback failed for %s: %s (continuing)\033[0m\n", action.ResourceAddr, err.Error())
		} else {
			action.Status = StatusRolledBack
			fmt.Printf("  \033[32m  ✓ Rolled back: %s\033[0m\n", action.ResourceAddr)
		}
		o.mu.Unlock()

		o.saveState()
	}
}
