from __future__ import annotations

from typing import Any

from ..models.resource import (
    DriftResult, DriftItem, DriftType, RiskLevel, TfResource,
)


def generate_remediations(
    results: list[DriftResult],
    state_resources: dict[str, TfResource] | None = None,
) -> list[DriftResult]:
    for result in results:
        result.remediations = []
        for drift in result.drifts:
            remediation = _remediate_drift(drift, result, state_resources)
            if remediation:
                result.remediations.append(remediation)
    return results


def _remediate_drift(
    drift: DriftItem,
    result: DriftResult,
    state_resources: dict[str, TfResource] | None = None,
) -> dict[str, Any] | None:
    if drift.drift_type == DriftType.ATTRIBUTE_CHANGED:
        return _remediate_attribute_changed(drift, result)
    elif drift.drift_type == DriftType.RESOURCE_MISSING:
        return _remediate_resource_missing(drift, result, state_resources)
    elif drift.drift_type == DriftType.ORPHAN_RESOURCE:
        return _remediate_orphan_resource(drift, result)
    elif drift.drift_type == DriftType.ATTRIBUTE_MISSING:
        return _remediate_attribute_missing(drift, result)
    elif drift.drift_type == DriftType.EXTRA_ATTRIBUTE:
        return _remediate_extra_attribute(drift, result)
    elif drift.drift_type == DriftType.TYPE_MISMATCH:
        return _remediate_type_mismatch(drift, result)
    return None


def _remediate_attribute_changed(drift: DriftItem, result: DriftResult) -> dict[str, Any]:
    attr_name = drift.attribute_path.rsplit(".", 1)[-1]
    is_rebuild = attr_name in {
        "instance_type", "ami", "image_id", "instance_class",
        "engine", "engine_version", "multi_az", "storage_type",
        "allocated_storage", "node_type", "machine_type", "disk_size",
        "image", "size",
    }

    options = []

    options.append({
        "action": "terraform apply",
        "description": f"Apply configuration to update actual state to match desired: {drift.attribute_path}",
        "command": "terraform apply -target={}".format(drift.resource_address),
        "risk": "high" if is_rebuild else "low",
        "note": "This will rebuild the resource" if is_rebuild else "This will update the resource in-place",
    })

    options.append({
        "action": "update config",
        "description": f"Modify configuration to match current actual state for {drift.attribute_path}",
        "command": f"# Edit config: set {drift.attribute_path} = {drift.state_value!r}",
        "risk": "low",
        "note": "Accept current state as desired state",
    })

    return {
        "drift_type": drift.drift_type.value,
        "resource": drift.resource_address,
        "attribute": drift.attribute_path,
        "config_value": _serialize(drift.config_value),
        "state_value": _serialize(drift.state_value),
        "options": options,
        "recommended": options[0] if drift.risk_level != RiskLevel.HIGH else options[1],
        "risk_level": drift.risk_level.value,
    }


def _remediate_resource_missing(
    drift: DriftItem,
    result: DriftResult,
    state_resources: dict[str, TfResource] | None = None,
) -> dict[str, Any]:
    resource_addr = drift.resource_address
    parts = resource_addr.split(".")
    resource_type = parts[0] if len(parts) >= 1 else ""
    resource_name = parts[1] if len(parts) >= 2 else ""

    resource_id_placeholder = "<RESOURCE_ID>"
    if state_resources:
        for addr, res in state_resources.items():
            if res.resource_type == resource_type and res.resource_name == resource_name:
                if res.resource_id:
                    resource_id_placeholder = res.resource_id
                    break

    options = [
        {
            "action": "terraform import",
            "description": f"Import existing resource into Terraform state",
            "command": f"terraform import {resource_addr} {resource_id_placeholder}",
            "risk": "medium",
            "note": "Ensure the resource ID is correct before importing",
        },
        {
            "action": "terraform apply",
            "description": f"Create the resource as defined in configuration",
            "command": f"terraform apply -target={resource_addr}",
            "risk": "high",
            "note": "This will create a NEW resource (may duplicate existing infrastructure)",
        },
    ]

    return {
        "drift_type": drift.drift_type.value,
        "resource": resource_addr,
        "attribute": "*",
        "options": options,
        "recommended": options[0],
        "risk_level": drift.risk_level.value,
    }


def _remediate_orphan_resource(drift: DriftItem, result: DriftResult) -> dict[str, Any]:
    resource_addr = drift.resource_address

    options = [
        {
            "action": "terraform state rm",
            "description": f"Remove orphan resource from state (resource no longer in config)",
            "command": f"terraform state rm {resource_addr}",
            "risk": "medium",
            "note": "The actual cloud resource will NOT be destroyed",
        },
        {
            "action": "restore config",
            "description": f"Add the resource definition back to configuration files",
            "command": f"# Add resource block for {resource_addr} to .tf files",
            "risk": "low",
            "note": "Accept the resource as managed infrastructure",
        },
    ]

    return {
        "drift_type": drift.drift_type.value,
        "resource": resource_addr,
        "attribute": "*",
        "options": options,
        "recommended": options[0],
        "risk_level": drift.risk_level.value,
    }


def _remediate_attribute_missing(drift: DriftItem, result: DriftResult) -> dict[str, Any]:
    options = [
        {
            "action": "terraform apply",
            "description": f"Apply to create attribute {drift.attribute_path} in actual state",
            "command": f"terraform apply -target={drift.resource_address}",
            "risk": "medium",
            "note": "New configuration attribute not yet applied",
        },
        {
            "action": "remove from config",
            "description": f"Remove the undeclared attribute from configuration",
            "command": f"# Remove {drift.attribute_path} from {drift.resource_address} config",
            "risk": "low",
            "note": "Only if the attribute was added by mistake",
        },
    ]

    return {
        "drift_type": drift.drift_type.value,
        "resource": drift.resource_address,
        "attribute": drift.attribute_path,
        "config_value": _serialize(drift.config_value),
        "options": options,
        "recommended": options[0],
        "risk_level": drift.risk_level.value,
    }


def _remediate_extra_attribute(drift: DriftItem, result: DriftResult) -> dict[str, Any]:
    options = [
        {
            "action": "accept as default",
            "description": f"Attribute {drift.attribute_path} is likely a provider default or computed value",
            "command": "# No action needed - provider-set default",
            "risk": "low",
            "note": "Provider automatically fills this attribute",
        },
        {
            "action": "add to config",
            "description": f"Explicitly declare {drift.attribute_path} in configuration",
            "command": f"# Add {drift.attribute_path} = {_serialize(drift.state_value)!r} to config",
            "risk": "low",
            "note": "Make the implicit explicit for tracking",
        },
    ]

    return {
        "drift_type": drift.drift_type.value,
        "resource": drift.resource_address,
        "attribute": drift.attribute_path,
        "state_value": _serialize(drift.state_value),
        "options": options,
        "recommended": options[0],
        "risk_level": drift.risk_level.value,
    }


def _remediate_type_mismatch(drift: DriftItem, result: DriftResult) -> dict[str, Any]:
    options = [
        {
            "action": "terraform apply",
            "description": f"Apply to reconcile type mismatch for {drift.attribute_path}",
            "command": f"terraform apply -target={drift.resource_address}",
            "risk": "medium",
            "note": f"Expected {drift.expected_type}, got {drift.actual_type}",
        },
        {
            "action": "fix config type",
            "description": f"Update config value type to match state",
            "command": f"# Change {drift.attribute_path} to {drift.actual_type} type: {_serialize(drift.state_value)!r}",
            "risk": "low",
            "note": "Align configuration type with actual state",
        },
    ]

    return {
        "drift_type": drift.drift_type.value,
        "resource": drift.resource_address,
        "attribute": drift.attribute_path,
        "expected_type": drift.expected_type,
        "actual_type": drift.actual_type,
        "options": options,
        "recommended": options[1],
        "risk_level": drift.risk_level.value,
    }


def _serialize(val: Any) -> Any:
    if isinstance(val, (dict, list)):
        return val
    if val is None:
        return None
    return str(val)
