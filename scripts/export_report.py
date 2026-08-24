"""Export an analyzer report for the static viewer."""

import argparse
import json
from pathlib import Path


def export_report(source: Path, destination: Path) -> None:
    """Copy and validate a report into a viewer directory."""
    report = json.loads(source.read_text(encoding="utf-8"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Export report.json for the static viewer")
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    export_report(args.source, args.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
