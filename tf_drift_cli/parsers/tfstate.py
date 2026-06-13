from __future__ import annotations

import json
import os
from typing import Any, Generator

from ..models.resource import TfResource, ResourceRef
from ..models.graph import DependencyGraph

SENSITIVE_MASK = "[SENSITIVE]"
LARGE_FILE_THRESHOLD = 500


def _parse_reference(ref_str: str) -> ResourceRef:
    parts = ref_str.split(".")
    module_path = None
    idx = 0

    if parts and parts[0] == "module" and len(parts) >= 2:
        module_path = parts[1]
        idx = 2

    resource_type = None
    resource_name = None
    attribute = None

    remaining = parts[idx:]
    if len(remaining) >= 2:
        resource_type = remaining[0]
        name_part = remaining[1]
        bracket_idx = name_part.find("[")
        if bracket_idx >= 0:
            resource_name = name_part[:bracket_idx]
        else:
            resource_name = name_part
        if len(remaining) > 2:
            attribute = ".".join(remaining[2:])
    elif len(remaining) == 1:
        if remaining[0] in ("var", "local", "data"):
            return ResourceRef(
                ref_type=remaining[0],
                module_path=module_path,
                resource_type=None,
                resource_name=None,
                attribute=None,
                raw=ref_str,
            )

    ref_type = "resource"
    if resource_type == "data":
        ref_type = "data"
    elif resource_type == "var":
        ref_type = "var"
    elif resource_type == "local":
        ref_type = "local"

    return ResourceRef(
        ref_type=ref_type,
        module_path=module_path,
        resource_type=resource_type,
        resource_name=resource_name,
        attribute=attribute,
        raw=ref_str,
    )


def _extract_references(attributes: dict[str, Any]) -> list[ResourceRef]:
    refs: list[ResourceRef] = []
    seen: set[str] = set()

    def _scan_value(val: Any):
        if isinstance(val, str):
            if val.startswith("var.") or val.startswith("local.") or val.startswith("data."):
                if val not in seen:
                    seen.add(val)
                    refs.append(_parse_reference(val))
            elif "." in val and not val.startswith(("arn:", "http:", "https:", "i-")):
                parts = val.split(".")
                if len(parts) >= 2 and parts[0] not in ("", "cidr", "tcp", "udp"):
                    if val not in seen:
                        seen.add(val)
                        refs.append(_parse_reference(val))
        elif isinstance(val, list):
            for item in val:
                _scan_value(item)
        elif isinstance(val, dict):
            for v in val.values():
                _scan_value(v)

    for attr_val in attributes.values():
        _scan_value(attr_val)

    return refs


def _extract_sensitive_keys(attributes: dict[str, Any], prefix: str = "") -> set[str]:
    result: set[str] = set()
    for key, value in attributes.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if key == "sensitive" and value is True:
            parent = prefix.rsplit(".", 1)[-1] if prefix else ""
            if parent:
                result.add(parent)
        elif isinstance(value, dict):
            result.update(_extract_sensitive_keys(value, full_key))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    result.update(_extract_sensitive_keys(item, f"{full_key}.{i}"))
    return result


def _mask_sensitive(attributes: dict[str, Any], sensitive_keys: set[str], prefix: str = "") -> dict[str, Any]:
    masked: dict[str, Any] = {}
    for key, value in attributes.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if full_key in sensitive_keys or key in sensitive_keys:
            masked[key] = SENSITIVE_MASK
        elif isinstance(value, dict):
            masked[key] = _mask_sensitive(value, sensitive_keys, full_key)
        elif isinstance(value, list):
            new_list: list[Any] = []
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    new_list.append(_mask_sensitive(item, sensitive_keys, f"{full_key}.{i}"))
                else:
                    new_list.append(item)
            masked[key] = new_list
        else:
            masked[key] = value
    return masked


def _parse_resource_instance(
    addr: str,
    mode: str,
    resource_type: str,
    resource_name: str,
    instance_key: str | int | None,
    instance_data: dict[str, Any],
    module_path: str | None,
) -> TfResource:
    attributes = instance_data.get("attributes", {})
    sensitive_raw = instance_data.get("sensitive_attributes", [])

    sensitive_keys: set[str] = set()
    if isinstance(sensitive_raw, list):
        for item in sensitive_raw:
            if isinstance(item, str) and item.startswith("$."):
                key = item[2:]
                sensitive_keys.add(key)
            elif isinstance(item, str):
                sensitive_keys.add(item)

    sensitive_keys.update(_extract_sensitive_keys(attributes))

    depends_on = instance_data.get("dependencies", [])

    references = _extract_references(attributes)

    provider_key = instance_data.get("provider_name", "")
    if not provider_key:
        provider_key = attributes.get("provider", "")

    create_time = attributes.get("create_time") or attributes.get("created_at") or attributes.get("creation_timestamp")
    resource_id = attributes.get("id")

    is_for_each = instance_key is not None and isinstance(instance_key, str)
    is_count = instance_key is not None and isinstance(instance_key, int)

    for_each_key = instance_key if is_for_each else None

    known_provider_prefixes = (
        "aws_", "azurerm_", "google_", "oci_", "alicloud_", "huaweicloud_",
        "vsphere_", "openstack_", "helm_", "kubernetes_", "k8s_",
        "docker_", "null_", "random_", "local_", "tls_", "vault_",
    )
    is_unknown_provider = not resource_type.startswith(known_provider_prefixes)

    masked_attrs = _mask_sensitive(attributes, sensitive_keys)

    computed_keys: set[str] = set()
    for k, v in attributes.items():
        if isinstance(v, str) and v == "":
            pass

    return TfResource(
        address=addr,
        resource_type=resource_type,
        resource_name=resource_name,
        provider=provider_key,
        module_path=module_path,
        index=instance_key,
        attributes=masked_attrs,
        sensitive_keys=sensitive_keys,
        depends_on=depends_on,
        references=references,
        create_time=create_time,
        resource_id=resource_id,
        is_for_each=is_for_each,
        is_count=is_count,
        for_each_key=for_each_key,
        computed_keys=computed_keys,
        provider_name=provider_key,
        is_unknown_provider=is_unknown_provider,
    )


def parse_tfstate_file(
    file_path: str,
    workspace: str | None = None,
) -> tuple[dict[str, TfResource], DependencyGraph]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"State file not found: {file_path}")

    file_size = os.path.getsize(file_path)

    if file_size > 50 * 1024 * 1024:
        return _parse_large_tfstate(file_path, workspace)

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return _parse_tfstate_data(data, workspace)


def _parse_tfstate_data(
    data: dict[str, Any],
    workspace: str | None = None,
) -> tuple[dict[str, TfResource], DependencyGraph]:
    version = data.get("version", 0)
    if version != 4:
        pass

    resources_data = data.get("resources", [])

    all_resources: dict[str, TfResource] = {}
    graph = DependencyGraph()

    for res in resources_data:
        mode = res.get("mode", "managed")
        if mode == "data":
            continue

        resource_type = res.get("type", "unknown")
        resource_name = res.get("name", "unknown")
        module_path = res.get("module", None)
        if module_path and module_path.startswith("module."):
            module_path = module_path[len("module."):]

        instances = res.get("instances", [])

        if not instances:
            addr = f"{resource_type}.{resource_name}"
            if module_path:
                addr = f"module.{module_path}.{addr}"
            continue

        for idx, instance in enumerate(instances):
            instance_key = instance.get("index_key", idx)

            base_addr = f"{resource_type}.{resource_name}"
            if module_path:
                base_addr = f"module.{module_path}.{base_addr}"

            if isinstance(instance_key, str):
                full_addr = f"{base_addr}[\"{instance_key}\"]"
            elif isinstance(instance_key, int) and instance_key != idx:
                full_addr = f"{base_addr}[{instance_key}]"
            else:
                if len(instances) > 1:
                    full_addr = f"{base_addr}[{idx}]"
                else:
                    full_addr = base_addr

            tf_res = _parse_resource_instance(
                addr=full_addr,
                mode=mode,
                resource_type=resource_type,
                resource_name=resource_name,
                instance_key=instance_key if instance_key != idx else None,
                instance_data=instance,
                module_path=module_path,
            )

            all_resources[full_addr] = tf_res
            graph.add_resource(tf_res)

    graph.build_from_references(all_resources)

    return all_resources, graph


def _parse_large_tfstate(
    file_path: str,
    workspace: str | None = None,
) -> tuple[dict[str, TfResource], DependencyGraph]:
    resources: dict[str, TfResource] = {}
    graph = DependencyGraph()

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    result = _parse_tfstate_data(data, workspace)
    return result


def stream_tfstate_resources(
    file_path: str,
) -> Generator[TfResource, None, None]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"State file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    resources_data = data.get("resources", [])

    for res in resources_data:
        mode = res.get("mode", "managed")
        if mode == "data":
            continue

        resource_type = res.get("type", "unknown")
        resource_name = res.get("name", "unknown")
        module_path = res.get("module", None)
        if module_path and module_path.startswith("module."):
            module_path = module_path[len("module."):]

        instances = res.get("instances", [])
        for idx, instance in enumerate(instances):
            instance_key = instance.get("index_key", idx)

            base_addr = f"{resource_type}.{resource_name}"
            if module_path:
                base_addr = f"module.{module_path}.{base_addr}"

            if isinstance(instance_key, str):
                full_addr = f"{base_addr}[\"{instance_key}\"]"
            elif isinstance(instance_key, int) and instance_key != idx:
                full_addr = f"{base_addr}[{instance_key}]"
            else:
                if len(instances) > 1:
                    full_addr = f"{base_addr}[{idx}]"
                else:
                    full_addr = base_addr

            yield _parse_resource_instance(
                addr=full_addr,
                mode=mode,
                resource_type=resource_type,
                resource_name=resource_name,
                instance_key=instance_key if instance_key != idx else None,
                instance_data=instance,
                module_path=module_path,
            )
