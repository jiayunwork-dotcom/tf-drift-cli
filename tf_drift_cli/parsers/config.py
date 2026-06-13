from __future__ import annotations

import os
from typing import Any

import yaml

from ..models.resource import DriftConfig, IgnoreRule


def parse_drift_config(config_path: str) -> DriftConfig:
    if not os.path.exists(config_path):
        return DriftConfig()

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or not isinstance(data, dict):
        return DriftConfig()

    config = DriftConfig()

    config.default_format = data.get("format", "terminal")
    config.exit_code_threshold = data.get("exit_code_threshold", "any")
    config.state_file = data.get("state_file")
    config.config_dir = data.get("config_dir")
    config.workspace = data.get("workspace")

    ignore_list = data.get("ignore", [])
    if isinstance(ignore_list, list):
        for item in ignore_list:
            if isinstance(item, str):
                if "." in item:
                    parts = item.split(".", 2)
                    if len(parts) >= 2:
                        config.ignore_rules.append(IgnoreRule(
                            resource_type=parts[0],
                            resource_name=parts[1],
                            attribute_name=parts[2] if len(parts) > 2 else None,
                        ))
                else:
                    config.ignore_rules.append(IgnoreRule(resource_type=item))
            elif isinstance(item, dict):
                config.ignore_rules.append(IgnoreRule(
                    resource_type=item.get("resource_type"),
                    resource_name=item.get("resource_name"),
                    attribute_name=item.get("attribute_name"),
                    tags=item.get("tags"),
                ))

    return config


def find_drift_config(start_dir: str) -> str | None:
    candidates = [".tfdrift.yaml", ".tfdrift.yml", "tfdrift.yaml", "tfdrift.yml"]
    current = os.path.abspath(start_dir)

    while True:
        for name in candidates:
            path = os.path.join(current, name)
            if os.path.exists(path):
                return path
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    return None
