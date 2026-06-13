from __future__ import annotations

import json
from typing import Any

from ..models.resource import (
    DriftReport, DriftResult, DriftItem, DriftType, RiskLevel,
)


def format_json(report: DriftReport) -> str:
    data = _report_to_dict(report)
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _report_to_dict(report: DriftReport) -> dict[str, Any]:
    return {
        "timestamp": report.timestamp,
        "state_file": report.state_file,
        "config_dir": report.config_dir,
        "workspace": report.workspace,
        "summary": {
            "total_resources_in_state": report.total_resources_in_state,
            "total_resources_in_config": report.total_resources_in_config,
            "total_drifts": report.total_drifts,
            "high_risk_count": report.high_risk_count,
            "medium_risk_count": report.medium_risk_count,
            "low_risk_count": report.low_risk_count,
            "ignored_count": report.ignored_count,
        },
        "results": [_result_to_dict(r) for r in report.results],
        "environment_diffs": report.environment_diffs,
    }


def _result_to_dict(result: DriftResult) -> dict[str, Any]:
    return {
        "resource_address": result.resource_address,
        "resource_type": result.resource_type,
        "max_risk": result.max_risk.value,
        "drifts": [_drift_to_dict(d) for d in result.drifts],
        "impacted_resources": [
            {
                "resource_address": imp.resource_address,
                "level": imp.level,
                "propagation_path": imp.propagation_path,
                "drift_attribute": imp.drift_attribute,
            }
            for imp in result.impacted_resources
        ],
        "remediations": result.remediations,
    }


def _drift_to_dict(drift: DriftItem) -> dict[str, Any]:
    d: dict[str, Any] = {
        "type": drift.drift_type.value,
        "resource": drift.resource_address,
        "attribute": drift.attribute_path,
        "config_value": _serialize(drift.config_value),
        "state_value": _serialize(drift.state_value),
        "risk_level": drift.risk_level.value,
    }
    if drift.drift_type == DriftType.TYPE_MISMATCH:
        d["expected_type"] = drift.expected_type
        d["actual_type"] = drift.actual_type
    return d


def _serialize(val: Any) -> Any:
    if isinstance(val, (dict, list, int, float, bool)):
        return val
    if val is None:
        return None
    return str(val)
