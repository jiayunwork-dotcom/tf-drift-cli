from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .models.resource import DriftConfig, IgnoreRule, RiskLevel
from .parsers.tfstate import parse_tfstate_file
from .parsers.hcl_parser import parse_config_dir
from .parsers.config import parse_drift_config, find_drift_config
from .engine.detector import DriftDetector, run_detection
from .engine.impact import analyze_impact
from .remediation.advisor import generate_remediations
from .multi_env.comparator import compare_environments, format_diff_matrix
from .reporters.terminal import format_terminal
from .reporters.json_report import format_json
from .reporters.markdown import format_markdown
from .reporters.html_report import format_html


BASELINE_DIR = ".tfdrift"


def _parse_ignore_arg(ignore_list: list[str]) -> list[IgnoreRule]:
    rules: list[IgnoreRule] = []
    for item in ignore_list:
        if "." in item:
            parts = item.split(".", 2)
            if len(parts) >= 2:
                rules.append(IgnoreRule(
                    resource_type=parts[0],
                    resource_name=parts[1],
                    attribute_name=parts[2] if len(parts) > 2 else None,
                ))
        else:
            rules.append(IgnoreRule(resource_type=item))
    return rules


def _save_baseline(report: Any, baseline_path: str):
    os.makedirs(os.path.dirname(baseline_path) or ".", exist_ok=True)
    drift_keys: list[str] = []
    for result in report.results:
        for drift in result.drifts:
            key = f"{drift.resource_address}::{drift.drift_type.value}::{drift.attribute_path}"
            drift_keys.append(key)

    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": report.timestamp,
            "state_file": report.state_file,
            "config_dir": report.config_dir,
            "drift_keys": drift_keys,
        }, f, indent=2)


def _load_baseline(baseline_path: str) -> set[str]:
    if not os.path.exists(baseline_path):
        return set()
    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return set(data.get("drift_keys", []))


def _get_exit_code(report: Any, threshold: str) -> int:
    if report.total_drifts == 0:
        return 0

    if threshold == "any":
        return 1
    elif threshold == "high":
        return 2 if report.high_risk_count > 0 else 0
    elif threshold == "medium":
        return 2 if (report.high_risk_count > 0 or report.medium_risk_count > 0) else 0
    return 0


def _write_output(content: str, output_file: str | None):
    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        print(content)


def cmd_detect(args: argparse.Namespace):
    config_dir = args.config_dir
    state_file = args.state_file
    workspace = args.workspace
    output_format = args.format
    output_file = args.output

    file_config = DriftConfig()
    if not args.no_config and config_dir:
        config_path = find_drift_config(config_dir)
        if config_path:
            file_config = parse_drift_config(config_path)

    if not state_file:
        state_file = file_config.state_file or "terraform.tfstate"
    if not config_dir:
        config_dir = file_config.config_dir or "."
    if not workspace:
        workspace = file_config.workspace

    ignore_rules: list[IgnoreRule] = list(file_config.ignore_rules)
    if args.ignore:
        ignore_rules.extend(_parse_ignore_arg(args.ignore))

    baseline_drifts: set[str] = set()
    baseline_path = os.path.join(BASELINE_DIR, "baseline.json")
    if args.baseline:
        _save_baseline_flag = True
        baseline_path = args.baseline if isinstance(args.baseline, str) else baseline_path
    else:
        _save_baseline_flag = False

    if args.baseline_compare:
        baseline_drifts = _load_baseline(args.baseline_compare)

    report, dep_graph = run_detection(
        state_file=state_file,
        config_dir=config_dir,
        workspace=workspace,
        ignore_rules=ignore_rules,
        baseline_drifts=baseline_drifts,
    )

    analyze_impact(report.results, dep_graph)
    generate_remediations(report.results)

    report.ignored_count = sum(
        1 for r in report.results for d in r.drifts
        if any(rule.matches(r.resource_type, r.resource_address, d.attribute_path) for rule in ignore_rules)
    )

    if _save_baseline_flag if '_save_baseline_flag' in dir() else args.baseline:
        _save_baseline(report, baseline_path)

    if output_format == "terminal":
        content = format_terminal(report)
    elif output_format == "json":
        content = format_json(report)
    elif output_format == "markdown":
        content = format_markdown(report)
    elif output_format == "html":
        content = format_html(report)
    else:
        content = format_terminal(report)

    _write_output(content, output_file)

    threshold = args.exit_code or file_config.exit_code_threshold or "any"
    exit_code = _get_exit_code(report, threshold)
    if exit_code != 0:
        sys.exit(exit_code)


def cmd_compare(args: argparse.Namespace):
    state_files: dict[str, str] = {}
    for mapping in args.env_states:
        if "=" in mapping:
            name, path = mapping.split("=", 1)
            state_files[name] = path
        else:
            state_files[f"env{len(state_files)+1}"] = mapping

    if not state_files:
        print("Error: At least two state files required for comparison", file=sys.stderr)
        sys.exit(1)

    diffs = compare_environments(state_files, args.workspace)
    matrix = format_diff_matrix(diffs, list(state_files.keys()))

    output_format = args.format

    if output_format == "json":
        print(json.dumps(matrix, indent=2, default=str))
    elif output_format == "markdown":
        _print_env_markdown(matrix, list(state_files.keys()))
    elif output_format == "html":
        _print_env_html(matrix, list(state_files.keys()))
    else:
        _print_env_terminal(matrix, list(state_files.keys()))


def _print_env_terminal(matrix: list[dict], env_names: list[str]):
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Environment Comparison")
    table.add_column("Resource")
    table.add_column("Attribute")
    for env in env_names:
        table.add_column(env)
    table.add_column("Note")

    for row in matrix:
        vals = [str(row.get(env, "N/A")) for env in env_names]
        note = "⚠ PROD UNIQUE" if row.get("is_production_unique") else ""
        table.add_row(row["resource"], row["attribute"], *vals, note)

    console.print(table)


def _print_env_markdown(matrix: list[dict], env_names: list[str]):
    lines = ["# Environment Comparison\n"]
    header = "| Resource | Attribute | " + " | ".join(env_names) + " | Note |"
    sep = "|" + "|".join(["---"] * (len(env_names) + 3)) + "|"
    lines.append(header)
    lines.append(sep)
    for row in matrix:
        vals = [str(row.get(env, "N/A")) for env in env_names]
        note = "⚠️ PROD UNIQUE" if row.get("is_production_unique") else ""
        lines.append(f"| {row['resource']} | {row['attribute']} | " + " | ".join(vals) + f" | {note} |")
    print("\n".join(lines))


def _print_env_html(matrix: list[dict], env_names: list[str]):
    parts = ['<table border="1" cellpadding="6"><tr><th>Resource</th><th>Attribute</th>']
    for env in env_names:
        parts.append(f'<th>{env}</th>')
    parts.append('<th>Note</th></tr>')
    for row in matrix:
        vals = [f'<td>{row.get(env, "N/A")}</td>' for env in env_names]
        note = "⚠ PROD UNIQUE" if row.get("is_production_unique") else ""
        parts.append(f'<tr><td>{row["resource"]}</td><td>{row["attribute"]}</td>{"".join(vals)}<td>{note}</td></tr>')
    parts.append('</table>')
    print("\n".join(parts))


def cmd_baseline(args: argparse.Namespace):
    state_file = args.state_file or "terraform.tfstate"
    config_dir = args.config_dir or "."
    baseline_path = args.baseline_path or os.path.join(BASELINE_DIR, "baseline.json")

    report, _ = run_detection(state_file=state_file, config_dir=config_dir)
    _save_baseline(report, baseline_path)
    print(f"Baseline saved to {baseline_path} ({report.total_drifts} drifts recorded)")


def main():
    parser = argparse.ArgumentParser(
        prog="tf-drift",
        description="Terraform Infrastructure State Drift Detection & Remediation CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    detect_parser = subparsers.add_parser("detect", help="Detect drift between state and config")
    detect_parser.add_argument("--state-file", "-s", help="Path to terraform.tfstate file")
    detect_parser.add_argument("--config-dir", "-c", help="Path to Terraform config directory")
    detect_parser.add_argument("--workspace", "-w", help="Target workspace name")
    detect_parser.add_argument("--format", "-f", choices=["terminal", "json", "markdown", "html"],
                               default="terminal", help="Output format")
    detect_parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    detect_parser.add_argument("--ignore", "-i", action="append", default=[],
                               help="Ignore rules (resource_type or resource_type.name or resource_type.name.attr)")
    detect_parser.add_argument("--exit-code", choices=["any", "high", "medium"],
                               help="Exit code mode for CI")
    detect_parser.add_argument("--baseline", nargs="?", const=True, default=False,
                               help="Save current results as baseline")
    detect_parser.add_argument("--baseline-compare", metavar="BASELINE_FILE",
                               help="Compare against a baseline file (incremental mode)")
    detect_parser.add_argument("--no-config", action="store_true",
                               help="Ignore .tfdrift.yaml config file")

    compare_parser = subparsers.add_parser("compare", help="Compare drift across environments")
    compare_parser.add_argument("--env-states", "-e", nargs="+", required=True,
                                help="Environment state files (name=path format)")
    compare_parser.add_argument("--workspace", "-w", help="Workspace name")
    compare_parser.add_argument("--format", "-f", choices=["terminal", "json", "markdown", "html"],
                               default="terminal", help="Output format")

    baseline_parser = subparsers.add_parser("baseline", help="Save drift baseline")
    baseline_parser.add_argument("--state-file", "-s", help="Path to terraform.tfstate file")
    baseline_parser.add_argument("--config-dir", "-c", help="Path to Terraform config directory")
    baseline_parser.add_argument("--baseline-path", help="Path to save baseline file")

    args = parser.parse_args()

    if args.command == "detect":
        cmd_detect(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "baseline":
        cmd_baseline(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
