"""Command-line interface; importing this module never starts an audit."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .config import ConfigurationError, resolve_bundle_dir, validate_request_path
from .engine import run_audit, validate_output_file
from .models import AuditConfig


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ghost-audit", description="Local evidence-driven deletion audit")
    parser.add_argument("--verbose", action="store_true", help="Log progress without printing evidence contents")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="Print the installed package version")
    sub.add_parser("health", help="Check runtime and optional local OCR availability")
    run = sub.add_parser("run", help="Audit requests using a local evidence bundle")
    run.add_argument("--requests", required=True, type=Path, help="CSV of requests to audit")
    run.add_argument("--evidence-dir", required=True, type=Path,
                     help="Evidence bundle root or its evidence/ directory")
    run.add_argument("--output", required=True, type=Path, help="Destination CSV path")
    run.add_argument("--diagnostics", type=Path, help="Optional local candidate/provenance diagnostics JSON")
    validate = sub.add_parser("validate", help="Validate an output CSV against its request IDs")
    validate.add_argument("--requests", required=True, type=Path)
    validate.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "health":
        import sys as runtime_sys
        from . import engine

        print(f"ghost-audit {__version__}; Python {runtime_sys.version_info.major}.{runtime_sys.version_info.minor}")
        command = engine.find_tesseract_executable()
        print(f"Local OCR executable: {'available' if command else 'not available (OCR disabled)'}")
        print("Hosted model/network calls: disabled")
        return 0 if runtime_sys.version_info >= (3, 10) else 1
    try:
        requests_path = validate_request_path(args.requests)
        if args.command == "run":
            bundle_dir = resolve_bundle_dir(args.evidence_dir)
            summary = run_audit(AuditConfig(requests_path, bundle_dir, args.output, args.diagnostics))
            print(f"Wrote {summary.request_count} rows to {summary.output_path}")
            print("Status counts: " + ", ".join(f"{k}={v}" for k, v in summary.status_counts.items()))
            return 0
        issues = validate_output_file(args.output, requests_path)
        if issues:
            print("Validation failed:")
            for issue in issues[:50]:
                print(f"- {issue}")
            return 1
        print("Output validation passed.")
        return 0
    except (ConfigurationError, OSError, RuntimeError, ValueError) as exc:
        print(f"ghost-audit: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
