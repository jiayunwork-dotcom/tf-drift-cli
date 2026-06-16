package remediation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	StatusSkipped    ActionStatus = "skipped"
)

const DefaultActionTimeout = 300
const PostConditionTimeout = 60

type RemediationAction struct {
	ID              string       `json:"id"`
	ResourceAddr    string       `json:"resource_addr"`
	ActionType      ActionType   `json:"action_type"`
	Command         string       `json:"command"`
	RollbackCmd     string       `json:"rollback_command"`
	DependsOn       []string     `json:"depends_on"`
	Status          ActionStatus `json:"status"`
	StartedAt       string       `json:"started_at,omitempty"`
	FinishedAt      string       `json:"finished_at,omitempty"`
	DurationMs      int64        `json:"duration_ms,omitempty"`
	Error           string       `json:"error,omitempty"`
	RiskLevel       string       `json:"risk_level"`
	DriftType       string       `json:"drift_type"`
	Condition       string       `json:"condition"`
	Timeout         int          `json:"timeout"`
	PostCondition   string       `json:"post_condition"`
	PostConditionErr string      `json:"post_condition_error,omitempty"`
}

type ActionLayer struct {
	Level   int                 `json:"level"`
	Actions []*RemediationAction `json:"actions"`
}

type ExecutionPlan struct {
	Layers               []*ActionLayer `json:"layers"`
	CriticalPath         []string       `json:"critical_path"`
	EstimatedParallelism float64        `json:"estimated_parallelism"`
	TotalActions         int            `json:"total_actions"`
	TotalLayers          int            `json:"total_layers"`
}

type RemediateState struct {
	Actions   []*RemediationAction `json:"actions"`
	Plan      *ExecutionPlan       `json:"plan"`
	StartedAt string               `json:"started_at"`
	UpdatedAt string               `json:"updated_at"`
	Finished  bool                 `json:"finished"`
}

type Orchestrator struct {
	actions        []*RemediationAction
	actionMap      map[string]*RemediationAction
	plan           *ExecutionPlan
	depGraph       *models.DependencyGraph
	stateFile      string
	concurrency    int
	noRollback     bool
	dryRun         bool
	globalTimeout  int
	remediateCfg   *RemediateConfig
	mu             sync.Mutex
	writeMu        sync.Mutex
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

func WithGlobalTimeout(timeout int) OrchestratorOption {
	return func(o *Orchestrator) {
		if timeout > 0 {
			o.globalTimeout = timeout
		}
	}
}

func WithRemediateConfig(cfg *RemediateConfig) OrchestratorOption {
	return func(o *Orchestrator) {
		o.remediateCfg = cfg
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

		action := &RemediationAction{
			ID:           id,
			ResourceAddr: resourceAddr,
			ActionType:   actionType,
			Command:      cmd,
			RollbackCmd:  rollbackCmd,
			DependsOn:    []string{},
			Status:       StatusPending,
			RiskLevel:    string(result.MaxRisk),
			DriftType:    string(primaryDrift.DriftType),
		}

		for _, rem := range result.Remediations {
			if rem.Recommended != nil {
				if rem.Recommended.Condition != "" && action.Condition == "" {
					action.Condition = rem.Recommended.Condition
				}
				if rem.Recommended.Timeout > 0 && action.Timeout == 0 {
					action.Timeout = rem.Recommended.Timeout
				}
				if rem.Recommended.PostCondition != "" && action.PostCondition == "" {
					action.PostCondition = rem.Recommended.PostCondition
				}
				break
			}
		}

		o.applyActionConfig(action)

		o.actions = append(o.actions, action)
		o.actionMap[id] = action
		resourceActions[resourceAddr] = action
	}

	for _, action := range o.actions {
		if o.depGraph != nil {
			upstream := o.depGraph.GetUpstream(action.ResourceAddr)
			for depAddr := range upstream {
				if depAction, exists := resourceActions[depAddr]; exists {
					action.DependsOn = append(action.DependsOn, depAction.ID)
				}
			}
		}
	}
}

func (o *Orchestrator) applyActionConfig(action *RemediationAction) {
	if o.remediateCfg != nil {
		o.remediateCfg.ApplyToAction(action, o.globalTimeout)
	} else {
		if action.Timeout == 0 {
			if o.globalTimeout > 0 {
				action.Timeout = o.globalTimeout
			} else {
				action.Timeout = DefaultActionTimeout
			}
		}
		if action.PostCondition == "" && action.ActionType == ActionApply {
			action.PostCondition = fmt.Sprintf("terraform plan -detailed-exitcode -target=%s", action.ResourceAddr)
		}
	}
}

func (o *Orchestrator) buildDAG() {
	if len(o.actions) == 0 {
		o.plan = &ExecutionPlan{
			Layers:       []*ActionLayer{},
			TotalLayers:  0,
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

func (o *Orchestrator) ComputeRuntimeCriticalPath() []string {
	if len(o.actions) == 0 {
		return nil
	}

	longestDist := make(map[string]int)
	pred := make(map[string]string)

	for _, action := range o.actions {
		if action.Status == StatusSkipped || action.Status == StatusSuccess || action.Status == StatusRolledBack {
			longestDist[action.ID] = 0
		} else {
			longestDist[action.ID] = 0
		}
	}

	for _, layer := range o.plan.Layers {
		for _, action := range layer.Actions {
			if action.Status == StatusSkipped {
				continue
			}
			for _, depID := range action.DependsOn {
				depAction := o.actionMap[depID]
				if depAction == nil {
					continue
				}
				weight := 1
				if depAction.Status == StatusSkipped {
					weight = 0
				}
				if longestDist[depID]+weight > longestDist[action.ID] {
					longestDist[action.ID] = longestDist[depID] + weight
					pred[action.ID] = depID
				}
			}
		}
	}

	var endNode string
	maxDist := -1
	for id, dist := range longestDist {
		action := o.actionMap[id]
		if action.Status == StatusSkipped {
			continue
		}
		if dist > maxDist {
			maxDist = dist
			endNode = id
		}
	}

	var path []string
	current := endNode
	for current != "" {
		action := o.actionMap[current]
		if action.Status != StatusSkipped {
			path = append([]string{action.ResourceAddr}, path...)
		}
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
				"id":              action.ID,
				"resource_addr":   action.ResourceAddr,
				"action_type":     string(action.ActionType),
				"command":         action.Command,
				"depends_on":      action.DependsOn,
				"risk_level":      action.RiskLevel,
				"drift_type":      action.DriftType,
				"condition":       action.Condition,
				"timeout":         action.Timeout,
				"post_condition":  action.PostCondition,
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
			if action.Condition != "" {
				sb.WriteString(fmt.Sprintf("    │  Condition: %s\n", action.Condition))
			}
			if action.Timeout != DefaultActionTimeout {
				sb.WriteString(fmt.Sprintf("    │  Timeout:   %ds\n", action.Timeout))
			}
			if action.PostCondition != "" {
				sb.WriteString(fmt.Sprintf("    │  Post-Cond: %s\n", action.PostCondition))
			}
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
	o.writeMu.Lock()
	defer o.writeMu.Unlock()

	now := time.Now().Format(time.RFC3339)

	o.mu.Lock()
	finished := true
	for _, a := range o.actions {
		if a.Status == StatusPending || a.Status == StatusRunning {
			finished = false
			break
		}
	}

	actionsCopy := make([]*RemediationAction, len(o.actions))
	copy(actionsCopy, o.actions)
	o.mu.Unlock()

	state := &RemediateState{
		Actions:   actionsCopy,
		Plan:      o.plan,
		StartedAt: now,
		UpdatedAt: now,
		Finished:  finished,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := o.stateFile + ".tmp"
	dir := filepath.Dir(o.stateFile)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, o.stateFile); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
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

func isActionFinished(status ActionStatus) bool {
	return status == StatusSuccess || status == StatusRolledBack || status == StatusFailed || status == StatusSkipped
}

func (o *Orchestrator) Execute() error {
	if o.dryRun {
		return nil
	}

	o.saveState()

	var failedActions []*RemediationAction
	var completedSuccess []*RemediationAction
	var skippedActions []*RemediationAction
	rollbackLayers := make([][]*RemediationAction, 0, len(o.plan.Layers))
	hitFailure := false

	for layerIdx, layer := range o.plan.Layers {
		var toExecute []*RemediationAction
		var alreadyDone []*RemediationAction

		o.mu.Lock()
		for _, a := range layer.Actions {
			if isActionFinished(a.Status) {
				alreadyDone = append(alreadyDone, a)
			} else {
				toExecute = append(toExecute, a)
			}
		}
		o.mu.Unlock()

		if len(alreadyDone) > 0 {
			fmt.Printf("\n\033[1m[Layer %d/%d]\033[0m Skipping %d already processed action(s)\n",
				layerIdx+1, o.plan.TotalLayers, len(alreadyDone))
			for _, a := range alreadyDone {
				fmt.Printf("  \033[2m  ⊘ %s [%s] %s\033[0m\n",
					a.ResourceAddr, a.ActionType, a.Status)
			}
		}

		if len(toExecute) > 0 {
			fmt.Printf("\n\033[1m[Layer %d/%d]\033[0m Executing %d action(s) (concurrency: %d)\n",
				layerIdx+1, o.plan.TotalLayers, len(toExecute), o.concurrency)
		}

		var layerSuccess []*RemediationAction
		var layerFailed []*RemediationAction
		var layerSkipped []*RemediationAction

		if len(toExecute) > 0 {
			subLayer := &ActionLayer{Level: layer.Level, Actions: toExecute}
			results := o.executeLayer(subLayer)

			for _, r := range results {
				if r.Status == StatusSuccess {
					layerSuccess = append(layerSuccess, r)
					completedSuccess = append(completedSuccess, r)
				} else if r.Status == StatusFailed {
					layerFailed = append(layerFailed, r)
					failedActions = append(failedActions, r)
				} else if r.Status == StatusSkipped {
					layerSkipped = append(layerSkipped, r)
					skippedActions = append(skippedActions, r)
				}
			}
		} else {
			o.mu.Lock()
			for _, a := range layer.Actions {
				if a.Status == StatusSuccess {
					layerSuccess = append(layerSuccess, a)
					completedSuccess = append(completedSuccess, a)
				} else if a.Status == StatusFailed {
					layerFailed = append(layerFailed, a)
					failedActions = append(failedActions, a)
				} else if a.Status == StatusSkipped {
					layerSkipped = append(layerSkipped, a)
					skippedActions = append(skippedActions, a)
				}
			}
			o.mu.Unlock()
		}

		rollbackLayers = append([][]*RemediationAction{layerSuccess}, rollbackLayers...)

		if len(layerFailed) > 0 {
			hitFailure = true
			fmt.Printf("\n\033[31m\033[1m✗ Layer %d had failures, skipping remaining layers\033[0m\n", layerIdx+1)
			break
		}
	}

	if hitFailure && !o.noRollback && len(completedSuccess) > 0 {
		fmt.Printf("\n\033[33m\033[1m⚠ Entering rollback phase (%d actions to roll back)\033[0m\n", len(completedSuccess))
		o.executeRollbackByLayer(rollbackLayers)
	}

	if len(skippedActions) > 0 {
		fmt.Printf("\n\033[2m  %d action(s) skipped due to conditions\033[0m\n", len(skippedActions))
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
			if isActionFinished(a.Status) {
				o.mu.Unlock()
				results[idx] = a
				return
			}

			resourceType := extractResourceType(a.ResourceAddr)
			condVars := ConditionVars{
				RiskLevel:    a.RiskLevel,
				DriftType:    a.DriftType,
				ActionType:   string(a.ActionType),
				ResourceType: resourceType,
			}

			if a.Condition != "" {
				condResult, condErr := EvaluateCondition(a.Condition, condVars)
				if condErr != nil {
					a.Status = StatusFailed
					a.Error = fmt.Sprintf("condition evaluation error: %s", condErr.Error())
					a.FinishedAt = time.Now().Format(time.RFC3339)
					o.mu.Unlock()
					o.saveState()
					results[idx] = a
					return
				}
				if !condResult {
					a.Status = StatusSkipped
					a.FinishedAt = time.Now().Format(time.RFC3339)
					fmt.Printf("  \033[2m  ⊘ %s [%s] skipped (condition not met)\033[0m\n",
						a.ResourceAddr, a.ActionType)
					o.mu.Unlock()
					o.saveState()
					results[idx] = a
					return
				}
			}

			a.Status = StatusRunning
			a.StartedAt = time.Now().Format(time.RFC3339)
			o.mu.Unlock()

			if err := o.saveState(); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: failed to save state: %v\n", err)
			}

			fmt.Printf("  \033[36m[Layer %d/%d]\033[0m 执行: %s (%s)\n",
				layer.Level+1, o.plan.TotalLayers, a.ResourceAddr, string(a.ActionType))

			start := time.Now()
			err := o.runCommand(a.Command, a.Timeout)
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
				if a.PostCondition != "" {
					postErr := o.runCommand(a.PostCondition, PostConditionTimeout)
					if postErr != nil {
						a.Status = StatusFailed
						a.Error = fmt.Sprintf("post-condition failed: %s", postErr.Error())
						a.PostConditionErr = postErr.Error()
						fmt.Printf("  \033[31m  ✗ %s [%s] post-condition failed (%dms): %s\033[0m\n",
							a.ResourceAddr, a.ActionType, a.DurationMs, postErr.Error())
					} else {
						a.Status = StatusSuccess
						fmt.Printf("  \033[32m  ✓ %s [%s] success (%dms)\033[0m\n",
							a.ResourceAddr, a.ActionType, a.DurationMs)
					}
				} else {
					a.Status = StatusSuccess
					fmt.Printf("  \033[32m  ✓ %s [%s] success (%dms)\033[0m\n",
						a.ResourceAddr, a.ActionType, a.DurationMs)
				}
			}
			o.mu.Unlock()

			if err := o.saveState(); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: failed to save state: %v\n", err)
			}
			results[idx] = a
		}(i, action)
	}

	wg.Wait()
	return results
}

func (o *Orchestrator) runCommand(cmdStr string, timeoutSec int) error {
	if strings.HasPrefix(cmdStr, "#") || strings.HasPrefix(cmdStr, "<") {
		return nil
	}

	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := exec.Command(parts[0], parts[1:]...)

	done := make(chan error, 1)
	var output []byte
	var cmdErr error

	go func() {
		output, cmdErr = cmd.CombinedOutput()
		done <- cmdErr
	}()

	timeout := time.Duration(timeoutSec) * time.Second
	select {
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return fmt.Errorf("timeout exceeded after %d seconds", timeoutSec)
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%s: %s", err, string(output))
		}
		return nil
	}
}

func (o *Orchestrator) executeRollbackByLayer(rollbackLayers [][]*RemediationAction) {
	for layerIdx, layerActions := range rollbackLayers {
		if len(layerActions) == 0 {
			continue
		}
		fmt.Printf("  \033[33m\033[1mRollback Layer %d/%d:\033[0m %d action(s)\n",
			layerIdx+1, len(rollbackLayers), len(layerActions))

		for _, action := range layerActions {
			o.mu.Lock()
			status := action.Status
			o.mu.Unlock()

			if status == StatusSkipped {
				fmt.Printf("    \033[2m  ⊘ %s [%s] skipped, no rollback needed\033[0m\n",
					action.ResourceAddr, action.ActionType)
				continue
			}

			if status == StatusRolledBack || status == StatusFailed {
				fmt.Printf("    \033[2m  ⊘ %s [%s] already %s, skipping\033[0m\n",
					action.ResourceAddr, action.ActionType, status)
				continue
			}

			if action.RollbackCmd == "" {
				fmt.Printf("    \033[2m  ⊘ %s [%s] no rollback command\033[0m\n",
					action.ResourceAddr, action.ActionType)
				continue
			}

			fmt.Printf("    \033[33m  ↩ Rolling back: %s [%s]\033[0m\n",
				action.ResourceAddr, action.ActionType)
			err := o.runCommand(action.RollbackCmd, DefaultActionTimeout)

			o.mu.Lock()
			if err != nil {
				fmt.Printf("    \033[31m  ⚠ Rollback failed for %s: %s (continuing)\033[0m\n",
					action.ResourceAddr, err.Error())
			} else {
				action.Status = StatusRolledBack
				fmt.Printf("    \033[32m  ✓ Rolled back: %s\033[0m\n", action.ResourceAddr)
			}
			o.mu.Unlock()

			if err := o.saveState(); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: failed to save state: %v\n", err)
			}
		}
	}
}
