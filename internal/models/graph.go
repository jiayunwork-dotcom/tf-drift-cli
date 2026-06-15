package models

import (
	"container/list"
)

type DependencyGraph struct {
	Nodes        map[string]*TfResource
	Edges        map[string]map[string]bool
	ReverseEdges map[string]map[string]bool
}

func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Nodes:        make(map[string]*TfResource),
		Edges:        make(map[string]map[string]bool),
		ReverseEdges: make(map[string]map[string]bool),
	}
}

func (g *DependencyGraph) AddResource(res *TfResource) {
	addr := res.FullAddress()
	g.Nodes[addr] = res
	if _, ok := g.Edges[addr]; !ok {
		g.Edges[addr] = make(map[string]bool)
	}
	if _, ok := g.ReverseEdges[addr]; !ok {
		g.ReverseEdges[addr] = make(map[string]bool)
	}
	for _, dep := range res.DependsOn {
		g.AddEdge(addr, dep)
	}
}

func (g *DependencyGraph) AddEdge(from, to string) {
	if _, ok := g.Edges[from]; !ok {
		g.Edges[from] = make(map[string]bool)
	}
	g.Edges[from][to] = true
	if _, ok := g.ReverseEdges[to]; !ok {
		g.ReverseEdges[to] = make(map[string]bool)
	}
	g.ReverseEdges[to][from] = true
}

type LevelNode struct {
	ResourceAddr    string
	Level           int
	PropagationPath []string
}

func (g *DependencyGraph) GetDownstream(address string) map[int][]*LevelNode {
	levels := make(map[int][]*LevelNode)
	visited := make(map[string]bool)
	queue := list.New()

	for dep := range g.ReverseEdges[address] {
		if !visited[dep] {
			visited[dep] = true
			path := []string{address, dep}
			queue.PushBack(&LevelNode{
				ResourceAddr:    dep,
				Level:           1,
				PropagationPath: path,
			})
		}
	}

	for queue.Len() > 0 {
		elem := queue.Front()
		queue.Remove(elem)
		node := elem.Value.(*LevelNode)

		if _, ok := levels[node.Level]; !ok {
			levels[node.Level] = []*LevelNode{}
		}
		levels[node.Level] = append(levels[node.Level], node)

		for dep := range g.ReverseEdges[node.ResourceAddr] {
			if !visited[dep] {
				visited[dep] = true
				newPath := make([]string, len(node.PropagationPath)+1)
				copy(newPath, node.PropagationPath)
				newPath[len(newPath)-1] = dep
				queue.PushBack(&LevelNode{
					ResourceAddr:    dep,
					Level:           node.Level + 1,
					PropagationPath: newPath,
				})
			}
		}
	}

	return levels
}

func (g *DependencyGraph) GetUpstream(address string) map[string]bool {
	result := make(map[string]bool)
	queue := list.New()

	for dep := range g.Edges[address] {
		if !result[dep] {
			result[dep] = true
			queue.PushBack(dep)
		}
	}

	for queue.Len() > 0 {
		elem := queue.Front()
		queue.Remove(elem)
		node := elem.Value.(string)

		for dep := range g.Edges[node] {
			if !result[dep] {
				result[dep] = true
				queue.PushBack(dep)
			}
		}
	}

	return result
}

func (g *DependencyGraph) BuildFromReferences(resources map[string]*TfResource) {
	for addr, res := range resources {
		g.Nodes[addr] = res
		if _, ok := g.Edges[addr]; !ok {
			g.Edges[addr] = make(map[string]bool)
		}
		if _, ok := g.ReverseEdges[addr]; !ok {
			g.ReverseEdges[addr] = make(map[string]bool)
		}

		for _, dep := range res.DependsOn {
			if _, ok := resources[dep]; ok {
				g.AddEdge(addr, dep)
			}
		}
		for _, ref := range res.References {
			refAddr := ref.Address()
			if _, ok := resources[refAddr]; ok {
				g.AddEdge(addr, refAddr)
			}
		}
	}
}
