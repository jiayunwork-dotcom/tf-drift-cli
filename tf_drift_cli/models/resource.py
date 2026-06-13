from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DriftType(Enum):
    ATTRIBUTE_CHANGED = "attribute_changed"
    ATTRIBUTE_MISSING = "attribute_missing"
    EXTRA_ATTRIBUTE = "extra_attribute"
    RESOURCE_MISSING = "resource_missing"
    ORPHAN_RESOURCE = "orphan_resource"
    TYPE_MISMATCH = "type_mismatch"


class RiskLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ResourceRef:
    ref_type: str
    module_path: str | None
    resource_type: str | None
    resource_name: str | None
    attribute: str | None
    raw: str

    def address(self) -> str:
        parts: list[str] = []
        if self.module_path:
            parts.append(f"module.{self.module_path}")
        if self.resource_type and self.resource_name:
            parts.append(f"{self.resource_type}.{self.resource_name}")
        if self.attribute:
            parts.append(self.attribute)
        return ".".join(parts) if parts else self.raw


@dataclass
class TfResource:
    address: str
    resource_type: str
    resource_name: str
    provider: str
    module_path: str | None = None
    index: str | int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    sensitive_keys: set[str] = field(default_factory=set)
    depends_on: list[str] = field(default_factory=list)
    references: list[ResourceRef] = field(default_factory=list)
    create_time: str | None = None
    resource_id: str | None = None
    is_for_each: bool = False
    is_count: bool = False
    for_each_key: str | None = None
    computed_keys: set[str] = field(default_factory=set)
    provider_name: str | None = None
    is_unknown_provider: bool = False

    def full_address(self) -> str:
        if self.module_path:
            base = f"module.{self.module_path}.{self.resource_type}.{self.resource_name}"
        else:
            base = f"{self.resource_type}.{self.resource_name}"
        if self.index is not None:
            base += f"[{self.index}]"
        return base


@dataclass
class HclAttribute:
    key: str
    value: Any
    is_expression: bool = False
    expression_text: str | None = None
    references: list[ResourceRef] = field(default_factory=list)
    is_dynamic: bool = False
    is_conditional: bool = False


@dataclass
class HclBlock:
    block_type: str
    labels: list[str]
    attributes: dict[str, HclAttribute] = field(default_factory=dict)
    nested_blocks: list[HclBlock] = field(default_factory=dict)
    source_file: str | None = None
    source_line: int | None = None
    for_each_expr: str | None = None
    count_expr: str | None = None
    provider: str | None = None
    depends_on: list[str] = field(default_factory=list)

    def address(self) -> str:
        if self.block_type == "resource" and len(self.labels) >= 2:
            addr = f"{self.labels[0]}.{self.labels[1]}"
            if self.for_each_expr:
                return addr
            return addr
        return ".".join(self.labels) if self.labels else self.block_type


@dataclass
class HclConfig:
    resources: dict[str, HclBlock] = field(default_factory=dict)
    data_sources: dict[str, HclBlock] = field(default_factory=dict)
    variables: dict[str, HclBlock] = field(default_factory=dict)
    locals_: dict[str, HclAttribute] = field(default_factory=dict)
    outputs: dict[str, HclBlock] = field(default_factory=dict)
    modules: dict[str, HclBlock] = field(default_factory=dict)
    source_files: list[str] = field(default_factory=list)


@dataclass
class DriftItem:
    drift_type: DriftType
    resource_address: str
    attribute_path: str
    config_value: Any = None
    state_value: Any = None
    expected_type: str | None = None
    actual_type: str | None = None
    risk_level: RiskLevel = RiskLevel.LOW
    is_computed: bool = False
    is_nested: bool = False

    def severity_order(self) -> int:
        order = {
            DriftType.RESOURCE_MISSING: 0,
            DriftType.ORPHAN_RESOURCE: 1,
            DriftType.ATTRIBUTE_CHANGED: 2,
            DriftType.TYPE_MISMATCH: 3,
            DriftType.ATTRIBUTE_MISSING: 4,
            DriftType.EXTRA_ATTRIBUTE: 5,
        }
        return order.get(self.drift_type, 99)


@dataclass
class ImpactNode:
    resource_address: str
    level: int
    propagation_path: list[str]
    drift_attribute: str | None = None


@dataclass
class DriftResult:
    resource_address: str
    resource_type: str
    drifts: list[DriftItem] = field(default_factory=list)
    impacted_resources: list[ImpactNode] = field(default_factory=list)
    remediations: list[dict[str, Any]] = field(default_factory=list)
    max_risk: RiskLevel = RiskLevel.LOW

    def compute_max_risk(self):
        if not self.drifts:
            self.max_risk = RiskLevel.LOW
            return
        risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}
        self.max_risk = min(self.drifts, key=lambda d: risk_order[d.risk_level]).risk_level


@dataclass
class DriftReport:
    timestamp: str
    state_file: str
    config_dir: str
    workspace: str | None = None
    results: list[DriftResult] = field(default_factory=list)
    total_resources_in_state: int = 0
    total_resources_in_config: int = 0
    total_drifts: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    baseline_file: str | None = None
    ignored_count: int = 0
    environment_diffs: list[dict[str, Any]] = field(default_factory=list)

    def compute_summary(self):
        self.total_drifts = sum(len(r.drifts) for r in self.results)
        self.high_risk_count = sum(
            1 for r in self.results for d in r.drifts if d.risk_level == RiskLevel.HIGH
        )
        self.medium_risk_count = sum(
            1 for r in self.results for d in r.drifts if d.risk_level == RiskLevel.MEDIUM
        )
        self.low_risk_count = sum(
            1 for r in self.results for d in r.drifts if d.risk_level == RiskLevel.LOW
        )


@dataclass
class EnvironmentDiff:
    resource_address: str
    attribute_path: str
    values: dict[str, Any] = field(default_factory=dict)
    is_production_unique: bool = False


@dataclass
class IgnoreRule:
    resource_type: str | None = None
    resource_name: str | None = None
    attribute_name: str | None = None
    tags: dict[str, str] | None = None

    def matches(self, resource_type: str, resource_name: str, attribute_path: str | None = None) -> bool:
        if self.resource_type and self.resource_type != resource_type:
            return False
        if self.resource_name and self.resource_name != resource_name:
            return False
        if self.attribute_name and attribute_path and self.attribute_name != attribute_path:
            return False
        return True


@dataclass
class DriftConfig:
    ignore_rules: list[IgnoreRule] = field(default_factory=list)
    default_format: str = "terminal"
    exit_code_threshold: str = "any"
    state_file: str | None = None
    config_dir: str | None = None
    workspace: str | None = None
