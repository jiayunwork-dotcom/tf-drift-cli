from __future__ import annotations

from typing import Any

from ..models.resource import (
    TfResource, EnvironmentDiff, DriftReport,
)
from ..parsers.tfstate import parse_tfstate_file


def compare_environments(
    state_files: dict[str, str],
    workspace: str | None = None,
) -> list[EnvironmentDiff]:
    env_resources: dict[str, dict[str, TfResource]] = {}

    for env_name, file_path in state_files.items():
        resources, _ = parse_tfstate_file(file_path, workspace)
        env_resources[env_name] = resources

    all_resource_keys: set[str] = set()
    for env_name, resources in env_resources.items():
        for key, res in resources.items():
            normalized = f"{res.resource_type}.{res.resource_name}"
            all_resource_keys.add(normalized)

    diffs: list[EnvironmentDiff] = []
    env_names = list(state_files.keys())
    prod_name = None
    for name in env_names:
        if name in ("prod", "production", "prd"):
            prod_name = name
            break

    for res_key in sorted(all_resource_keys):
        env_attrs: dict[str, dict[str, Any]] = {}
        for env_name, resources in env_resources.items():
            for addr, res in resources.items():
                normalized = f"{res.resource_type}.{res.resource_name}"
                if normalized == res_key:
                    env_attrs[env_name] = res.attributes
                    break

        if len(env_attrs) < 2:
            continue

        all_attr_keys: set[str] = set()
        for attrs in env_attrs.values():
            all_attr_keys.update(attrs.keys())

        for attr_key in sorted(all_attr_keys):
            if attr_key.startswith("_") or attr_key.startswith("terraform_"):
                continue

            values: dict[str, Any] = {}
            for env_name, attrs in env_attrs.items():
                if attr_key in attrs:
                    values[env_name] = attrs[attr_key]

            unique_values = set()
            for v in values.values():
                unique_values.add(str(v))

            if len(unique_values) <= 1:
                continue

            is_prod_unique = False
            if prod_name and prod_name in values:
                prod_val = str(values[prod_name])
                non_prod_vals = set()
                for env_name, val in values.items():
                    if env_name != prod_name:
                        non_prod_vals.add(str(val))
                if len(non_prod_vals) == 1 and prod_val not in non_prod_vals:
                    is_prod_unique = True

            diffs.append(EnvironmentDiff(
                resource_address=res_key,
                attribute_path=attr_key,
                values=values,
                is_production_unique=is_prod_unique,
            ))

    return diffs


def format_diff_matrix(diffs: list[EnvironmentDiff], env_names: list[str]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []

    for diff in diffs:
        row: dict[str, Any] = {
            "resource": diff.resource_address,
            "attribute": diff.attribute_path,
        }
        for env_name in env_names:
            val = diff.values.get(env_name, "N/A")
            row[env_name] = val
        row["is_production_unique"] = diff.is_production_unique
        matrix.append(row)

    return matrix
