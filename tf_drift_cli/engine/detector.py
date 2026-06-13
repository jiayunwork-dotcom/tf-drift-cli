from __future__ import annotations

from typing import Any

from ..models.resource import (
    DriftItem, DriftResult, DriftReport, DriftType, RiskLevel,
    TfResource, HclBlock, HclConfig, HclAttribute, IgnoreRule,
)
from ..models.graph import DependencyGraph
from ..parsers.tfstate import parse_tfstate_file
from ..parsers.hcl_parser import parse_config_dir


META_ATTR_PREFIXES = ("_", "terraform_", "create_before_destroy")
COMPUTED_ATTRS = {
    "id", "arn", "owner_id", "creation_date", "created_time",
    "last_modified", "etag", "unique_id", "dns_name", "fqdn",
    "zone_id", "vpc_id", "subnet_id", "endpoint", "connection_string",
}


def _is_meta_attribute(key: str) -> bool:
    if key.startswith(META_ATTR_PREFIXES):
        return True
    known_meta = {
        "id", "create_time", "created_at", "destroy_time",
        "template_name", "schema_version", "raw_configuration",
    }
    return key in known_meta


def _is_computed_attribute(key: str, resource: TfResource) -> bool:
    if key in resource.computed_keys:
        return True
    if key in COMPUTED_ATTRS:
        return True
    return False


def _type_name(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "bool"
    if isinstance(val, int):
        return "int"
    if isinstance(val, float):
        return "float"
    if isinstance(val, str):
        return "string"
    if isinstance(val, list):
        return "list"
    if isinstance(val, dict):
        return "map"
    return type(val).__name__


def _values_equal(config_val: Any, state_val: Any, key: str) -> bool:
    if config_val is None and state_val is None:
        return True
    if config_val is None or state_val is None:
        return False

    if isinstance(config_val, str) and isinstance(state_val, (int, float)):
        try:
            if isinstance(state_val, float):
                return float(config_val) == state_val
            return int(config_val) == state_val
        except (ValueError, TypeError):
            return False

    if isinstance(state_val, str) and isinstance(config_val, (int, float)):
        try:
            if isinstance(config_val, float):
                return float(state_val) == config_val
            return int(state_val) == config_val
        except (ValueError, TypeError):
            return False

    if isinstance(config_val, (int, float)) and isinstance(state_val, (int, float)):
        return float(config_val) == float(state_val)

    if isinstance(config_val, bool) or isinstance(state_val, bool):
        return bool(config_val) == bool(state_val)

    if isinstance(config_val, list) and isinstance(state_val, list):
        return _lists_equal(config_val, state_val, key)

    if isinstance(config_val, dict) and isinstance(state_val, dict):
        return _maps_equal(config_val, state_val, key)

    return str(config_val) == str(state_val)


def _lists_equal(config_list: list, state_list: list, key: str) -> bool:
    if len(config_list) != len(state_list):
        return False

    has_unique_id = any(
        isinstance(item, dict) and ("name" in item or "id" in item)
        for item in config_list + state_list
        if isinstance(item, dict)
    )

    if has_unique_id:
        return _lists_equal_by_id(config_list, state_list)

    return config_list == state_list


def _lists_equal_by_id(config_list: list, state_list: list) -> bool:
    def _item_key(item: Any) -> str | None:
        if isinstance(item, dict):
            if "name" in item:
                return str(item["name"])
            if "id" in item:
                return str(item["id"])
        return None

    config_map: dict[str, Any] = {}
    for item in config_list:
        k = _item_key(item)
        if k:
            config_map[k] = item

    state_map: dict[str, Any] = {}
    for item in state_list:
        k = _item_key(item)
        if k:
            state_map[k] = item

    if set(config_map.keys()) != set(state_map.keys()):
        return False

    for k in config_map:
        if not _values_equal(config_map[k], state_map[k], k):
            return False

    return True


def _maps_equal(config_map: dict, state_map: dict, key: str) -> bool:
    all_keys = set(config_map.keys()) | set(state_map.keys())
    for k in all_keys:
        cv = config_map.get(k)
        sv = state_map.get(k)
        if not _values_equal(cv, sv, k):
            return False
    return True


def _flatten_hcl_attributes(block: HclBlock, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, attr in block.attributes.items():
        full_key = f"{prefix}.{key}" if prefix else key
        result[full_key] = attr.value
    for nested in block.nested_blocks:
        nested_prefix = f"{prefix}.{nested.block_type}" if prefix else nested.block_type
        if nested.labels:
            for label in nested.labels:
                label_prefix = f"{nested_prefix}.{label}" if label else nested_prefix
                result.update(_flatten_hcl_attributes(nested, label_prefix))
        else:
            result.update(_flatten_hcl_attributes(nested, nested_prefix))
    return result


def _flatten_state_attributes(attributes: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in attributes.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten_state_attributes(value, full_key))
        else:
            result[full_key] = value
    return result


def _match_config_to_state(
    config_key: str,
    state_attrs: dict[str, Any],
) -> str | None:
    if config_key in state_attrs:
        return config_key
    for state_key in state_attrs:
        if state_key.endswith(f".{config_key}") or config_key.endswith(f".{state_key}"):
            return state_key
    return None


REBUILD_TRIGGERING_ATTRS = {
    "instance_type", "ami", "image_id", "instance_class",
    "engine", "engine_version", "multi_az", "storage_type",
    "allocated_storage", "node_type", "cluster_type",
    "machine_type", "disk_size", "image", "size",
    "instance_count", "node_count", "replica_count",
}


class DriftDetector:
    def __init__(
        self,
        ignore_rules: list[IgnoreRule] | None = None,
        baseline_drifts: set[str] | None = None,
    ):
        self.ignore_rules = ignore_rules or []
        self.baseline_drifts = baseline_drifts or set()

    def _should_ignore(self, resource_type: str, resource_name: str, attr_path: str | None = None) -> bool:
        for rule in self.ignore_rules:
            if rule.matches(resource_type, resource_name, attr_path):
                return True
        return False

    def _is_baseline_drift(self, drift_key: str) -> bool:
        return drift_key in self.baseline_drifts

    def _make_drift_key(self, drift: DriftItem) -> str:
        return f"{drift.resource_address}::{drift.drift_type.value}::{drift.attribute_path}"

    def _assess_risk(self, drift: DriftItem, resource_type: str) -> RiskLevel:
        if drift.drift_type == DriftType.RESOURCE_MISSING:
            return RiskLevel.HIGH
        if drift.drift_type == DriftType.ORPHAN_RESOURCE:
            return RiskLevel.MEDIUM
        if drift.drift_type == DriftType.ATTRIBUTE_CHANGED:
            attr_name = drift.attribute_path.rsplit(".", 1)[-1]
            if attr_name in REBUILD_TRIGGERING_ATTRS:
                return RiskLevel.HIGH
            return RiskLevel.LOW
        if drift.drift_type == DriftType.TYPE_MISMATCH:
            return RiskLevel.MEDIUM
        if drift.drift_type == DriftType.ATTRIBUTE_MISSING:
            return RiskLevel.MEDIUM
        if drift.drift_type == DriftType.EXTRA_ATTRIBUTE:
            return RiskLevel.LOW
        return RiskLevel.LOW

    def detect(
        self,
        state_resources: dict[str, TfResource],
        config: HclConfig,
        dep_graph: DependencyGraph,
    ) -> DriftReport:
        import datetime
        report = DriftReport(
            timestamp=datetime.datetime.now().isoformat(),
            state_file="",
            config_dir="",
        )

        report.total_resources_in_state = len(state_resources)
        report.total_resources_in_config = len(config.resources)

        state_by_type_name: dict[str, list[TfResource]] = {}
        for addr, res in state_resources.items():
            key = f"{res.resource_type}.{res.resource_name}"
            if key not in state_by_type_name:
                state_by_type_name[key] = []
            state_by_type_name[key].append(res)

        for config_key, config_block in config.resources.items():
            if len(config_block.labels) >= 2:
                resource_type = config_block.labels[0]
                resource_name = config_block.labels[1]
            else:
                continue

            if self._should_ignore(resource_type, resource_name):
                continue

            state_key = f"{resource_type}.{resource_name}"
            state_matches = state_by_type_name.get(state_key, [])

            config_for_each = config_block.for_each_expr is not None
            config_count = config_block.count_expr is not None

            if not state_matches:
                if config_for_each or config_count:
                    pass
                else:
                    drift = DriftItem(
                        drift_type=DriftType.RESOURCE_MISSING,
                        resource_address=state_key,
                        attribute_path="*",
                        config_value="<defined in config>",
                        state_value="<not found in state>",
                        risk_level=RiskLevel.HIGH,
                    )
                    result = DriftResult(
                        resource_address=state_key,
                        resource_type=resource_type,
                        drifts=[drift],
                        max_risk=RiskLevel.HIGH,
                    )
                    report.results.append(result)
                continue

            for state_res in state_matches:
                result = self._compare_resource(state_res, config_block, dep_graph)
                if result.drifts:
                    result.compute_max_risk()
                    report.results.append(result)

        state_config_keys = set()
        for config_key, config_block in config.resources.items():
            if len(config_block.labels) >= 2:
                state_config_keys.add(f"{config_block.labels[0]}.{config_block.labels[1]}")

        for addr, state_res in state_resources.items():
            state_key = f"{state_res.resource_type}.{state_res.resource_name}"
            if state_key not in state_config_keys:
                if self._should_ignore(state_res.resource_type, state_res.resource_name):
                    continue

                drift = DriftItem(
                    drift_type=DriftType.ORPHAN_RESOURCE,
                    resource_address=addr,
                    attribute_path="*",
                    config_value="<not defined in config>",
                    state_value="<exists in state>",
                    risk_level=RiskLevel.MEDIUM,
                )
                result = DriftResult(
                    resource_address=addr,
                    resource_type=state_res.resource_type,
                    drifts=[drift],
                    max_risk=RiskLevel.MEDIUM,
                )
                report.results.append(result)

        report.compute_summary()
        return report

    def _compare_resource(
        self,
        state_res: TfResource,
        config_block: HclBlock,
        dep_graph: DependencyGraph,
    ) -> DriftResult:
        result = DriftResult(
            resource_address=state_res.full_address(),
            resource_type=state_res.resource_type,
        )

        config_attrs = _flatten_hcl_attributes(config_block)
        state_attrs = _flatten_state_attributes(state_res.attributes)

        for config_key, config_val in config_attrs.items():
            if _is_meta_attribute(config_key):
                continue

            attr_name = config_key.rsplit(".", 1)[-1]
            resource_name = config_block.labels[1] if len(config_block.labels) >= 2 else ""
            if self._should_ignore(state_res.resource_type, resource_name, config_key):
                continue

            matched_state_key = _match_config_to_state(config_key, state_attrs)

            if matched_state_key is None:
                if isinstance(config_val, str) and (
                    config_val.startswith("var.")
                    or config_val.startswith("local.")
                    or config_val.startswith("data.")
                    or config_val.startswith("module.")
                    or "${" in config_val
                ):
                    continue

                drift = DriftItem(
                    drift_type=DriftType.ATTRIBUTE_MISSING,
                    resource_address=state_res.full_address(),
                    attribute_path=config_key,
                    config_value=config_val,
                    state_value="<not present>",
                    risk_level=RiskLevel.MEDIUM,
                )
                drift.risk_level = self._assess_risk(drift, state_res.resource_type)
                drift_key = self._make_drift_key(drift)
                if not self._is_baseline_drift(drift_key):
                    result.drifts.append(drift)
                continue

            state_val = state_attrs[matched_state_key]

            if _is_computed_attribute(config_key, state_res):
                continue

            if isinstance(config_val, str) and (
                config_val.startswith("var.")
                or config_val.startswith("local.")
                or config_val.startswith("data.")
                or config_val.startswith("module.")
                or "${" in config_val
            ):
                continue

            if config_val is not None and state_val is not None:
                config_type = _type_name(config_val)
                state_type = _type_name(state_val)
                if config_type != state_type:
                    if not _values_equal(config_val, state_val, config_key):
                        if not (config_type in ("int", "float") and state_type in ("int", "float")):
                            drift = DriftItem(
                                drift_type=DriftType.TYPE_MISMATCH,
                                resource_address=state_res.full_address(),
                                attribute_path=config_key,
                                config_value=config_val,
                                state_value=state_val,
                                expected_type=config_type,
                                actual_type=state_type,
                                risk_level=RiskLevel.MEDIUM,
                            )
                            drift.risk_level = self._assess_risk(drift, state_res.resource_type)
                            drift_key = self._make_drift_key(drift)
                            if not self._is_baseline_drift(drift_key):
                                result.drifts.append(drift)
                            continue

            if not _values_equal(config_val, state_val, config_key):
                drift = DriftItem(
                    drift_type=DriftType.ATTRIBUTE_CHANGED,
                    resource_address=state_res.full_address(),
                    attribute_path=config_key,
                    config_value=config_val,
                    state_value=state_val,
                    risk_level=RiskLevel.LOW,
                )
                drift.risk_level = self._assess_risk(drift, state_res.resource_type)
                drift_key = self._make_drift_key(drift)
                if not self._is_baseline_drift(drift_key):
                    result.drifts.append(drift)

        for state_key, state_val in state_attrs.items():
            if _is_meta_attribute(state_key):
                continue
            if state_key in state_res.sensitive_keys:
                continue
            if _is_computed_attribute(state_key, state_res):
                continue

            matched = _match_config_to_state(state_key, config_attrs)
            if matched is not None:
                continue

            attr_name = state_key.rsplit(".", 1)[-1]
            resource_name = config_block.labels[1] if len(config_block.labels) >= 2 else ""
            if self._should_ignore(state_res.resource_type, resource_name, state_key):
                continue

            drift = DriftItem(
                drift_type=DriftType.EXTRA_ATTRIBUTE,
                resource_address=state_res.full_address(),
                attribute_path=state_key,
                config_value="<not declared>",
                state_value=state_val,
                risk_level=RiskLevel.LOW,
            )
            drift.risk_level = self._assess_risk(drift, state_res.resource_type)
            drift_key = self._make_drift_key(drift)
            if not self._is_baseline_drift(drift_key):
                result.drifts.append(drift)

        return result


def run_detection(
    state_file: str,
    config_dir: str,
    workspace: str | None = None,
    ignore_rules: list[IgnoreRule] | None = None,
    baseline_drifts: set[str] | None = None,
) -> DriftReport:
    state_resources, dep_graph = parse_tfstate_file(state_file, workspace)
    config = parse_config_dir(config_dir)

    detector = DriftDetector(ignore_rules=ignore_rules, baseline_drifts=baseline_drifts)
    report = detector.detect(state_resources, config, dep_graph)
    report.state_file = state_file
    report.config_dir = config_dir
    report.workspace = workspace

    return report, dep_graph
