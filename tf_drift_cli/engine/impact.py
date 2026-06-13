from __future__ import annotations

from typing import Any

from ..models.resource import DriftResult, DriftItem, ImpactNode, DriftType, RiskLevel
from ..models.graph import DependencyGraph


def analyze_impact(
    results: list[DriftResult],
    dep_graph: DependencyGraph,
) -> list[DriftResult]:
    for result in results:
        if not result.drifts:
            continue

        downstream = dep_graph.get_downstream(result.resource_address)
        impacted: list[ImpactNode] = []

        for level, nodes in downstream.items():
            for node_addr, path in nodes:
                impacted_drift_attrs: list[str] = []
                for drift in result.drifts:
                    if drift.drift_type in (
                        DriftType.ATTRIBUTE_CHANGED,
                        DriftType.ATTRIBUTE_MISSING,
                        DriftType.TYPE_MISMATCH,
                    ):
                        impacted_drift_attrs.append(drift.attribute_path)

                impacted.append(ImpactNode(
                    resource_address=node_addr,
                    level=level,
                    propagation_path=path,
                    drift_attribute=", ".join(impacted_drift_attrs) if impacted_drift_attrs else None,
                ))

        result.impacted_resources = impacted

        if impacted and result.max_risk == RiskLevel.LOW:
            for drift in result.drifts:
                if drift.risk_level == RiskLevel.LOW and impacted:
                    drift.risk_level = RiskLevel.MEDIUM
            result.compute_max_risk()

    return results


def format_impact_tree(result: DriftResult) -> list[dict[str, Any]]:
    if not result.impacted_resources:
        return []

    max_level = max(n.level for n in result.impacted_resources)
    tree: list[dict[str, Any]] = []

    for level in range(1, max_level + 1):
        level_nodes = [n for n in result.impacted_resources if n.level == level]
        for node in level_nodes:
            tree.append({
                "resource": node.resource_address,
                "level": node.level,
                "level_label": f"L{node.level} dependency",
                "propagation_path": " -> ".join(node.propagation_path),
                "drift_attribute": node.drift_attribute,
            })

    return tree
