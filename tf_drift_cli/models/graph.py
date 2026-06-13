from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from .resource import TfResource, ResourceRef


@dataclass
class DependencyGraph:
    nodes: dict[str, TfResource] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    reverse_edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_resource(self, resource: TfResource):
        addr = resource.full_address()
        self.nodes[addr] = resource
        for dep in resource.depends_on:
            self.edges[addr].add(dep)
            self.reverse_edges[dep].add(addr)

    def add_edge(self, from_addr: str, to_addr: str):
        self.edges[from_addr].add(to_addr)
        self.reverse_edges[to_addr].add(from_addr)

    def get_downstream(self, address: str) -> dict[int, list[tuple[str, list[str]]]]:
        levels: dict[int, list[tuple[str, list[str]]]] = {}
        visited: set[str] = set()
        queue: deque[tuple[str, int, list[str]]] = deque()

        for dep in self.reverse_edges.get(address, set()):
            path = [address, dep]
            queue.append((dep, 1, path))
            visited.add(dep)

        while queue:
            node, level, path = queue.popleft()
            if level not in levels:
                levels[level] = []
            levels[level].append((node, path))

            for dep in self.reverse_edges.get(node, set()):
                if dep not in visited:
                    visited.add(dep)
                    new_path = path + [dep]
                    queue.append((dep, level + 1, new_path))

        return levels

    def get_upstream(self, address: str) -> set[str]:
        result: set[str] = set()
        queue: deque[str] = deque(self.edges.get(address, set()))

        while queue:
            node = queue.popleft()
            if node not in result:
                result.add(node)
                queue.extend(self.edges.get(node, set()) - result)

        return result

    def topological_sort(self) -> list[str]:
        in_degree: dict[str, int] = defaultdict(int)
        for node in self.nodes:
            if node not in in_degree:
                in_degree[node] = 0
        for src, deps in self.edges.items():
            for _ in deps:
                in_degree[src] += 1

        queue: deque[str] = deque(n for n, d in in_degree.items() if d == 0)
        result: list[str] = []

        while queue:
            node = queue.popleft()
            result.append(node)
            for dep in self.reverse_edges.get(node, set()):
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    queue.append(dep)

        return result

    def build_from_references(self, resources: dict[str, TfResource]):
        for addr, resource in resources.items():
            self.nodes[addr] = resource
            for dep in resource.depends_on:
                if dep in resources:
                    self.edges[addr].add(dep)
                    self.reverse_edges[dep].add(addr)
            for ref in resource.references:
                ref_addr = ref.address()
                if ref_addr in resources:
                    self.edges[addr].add(ref_addr)
                    self.reverse_edges[ref_addr].add(addr)
