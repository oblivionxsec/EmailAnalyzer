"""Entry point for the email-analyzer command."""

import argparse
import json
from pathlib import Path
from time import perf_counter

from analyzer.core.parser import parse_message
from analyzer.core.local_tools import scan_report_attachments
from analyzer.core.report_builder import build_report


def analyze(input_path: Path, output_path: Path, verbose: bool = False, extract_all: bool = False, no_intel: bool = False, local_tools: bool = False, yara_rules: Path | None = None, clamav: bool = False) -> dict:
    """Analyze one .eml file and write its JSON report."""
    started = perf_counter()
    raw = input_path.read_bytes()
    parsed = parse_message(raw, recursive_attachments=extract_all)
    report = build_report(raw, parsed, round((perf_counter() - started) * 1000), source_name=input_path.name)
    if no_intel:
        report["threat_intel"] = {"mode": "disabled", "matches": []}
    scan_report_attachments(report, str(yara_rules) if local_tools and yara_rules else None, clamav if local_tools else False)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if verbose:
        print(f"Analyzed {input_path} -> {output_path}")
        print(f"Risk: {report['scoring']['category']} ({report['scoring']['score']}/100)")
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="email-analyzer", description="Offline deterministic email forensic analysis")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze_command = commands.add_parser("analyze", help="Analyze an .eml message")
    analyze_command.add_argument("input", type=Path)
    analyze_command.add_argument("-o", "--output", type=Path, default=Path("report.json"))
    analyze_command.add_argument("--verbose", action="store_true")
    analyze_command.add_argument("--extract-all", action="store_true", default=True, help="Extract nested attachments (enabled by default)")
    analyze_command.add_argument("--no-intel", action="store_true", help="Disable offline threat intelligence")
    analyze_command.add_argument("--local-tools", action="store_true", help="Run installed local analyzers without network access")
    analyze_command.add_argument("--yara-rules", type=Path, help="YARA rules file used with --local-tools")
    analyze_command.add_argument("--clamav", action="store_true", help="Use a local ClamAV daemon with --local-tools")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "analyze":
        analyze(args.input, args.output, args.verbose, args.extract_all, args.no_intel, args.local_tools, args.yara_rules, args.clamav)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
