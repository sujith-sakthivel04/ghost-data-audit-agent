"""Filesystem validation and evidence-bundle resolution."""

from __future__ import annotations

from pathlib import Path

REQUIRED_BUNDLE_FILES = (
    "evidence_files.csv",
    "user_identities.csv",
    "user_audit_log.csv",
    "system_activity.csv",
    "deletion_rules.csv",
)


class ConfigurationError(ValueError):
    """Raised when a supplied request file or evidence bundle is invalid."""


def resolve_bundle_dir(evidence_dir: Path) -> Path:
    """Resolve the bundle root from an explicit bundle root or its evidence/ folder."""
    evidence_dir = evidence_dir.expanduser().resolve()
    if not evidence_dir.exists() or not evidence_dir.is_dir():
        raise ConfigurationError(f"Evidence directory does not exist or is not a directory: {evidence_dir}")
    if (evidence_dir / "evidence_files.csv").is_file():
        bundle = evidence_dir
    elif evidence_dir.name.casefold() == "evidence" and (evidence_dir.parent / "evidence_files.csv").is_file():
        bundle = evidence_dir.parent
    else:
        raise ConfigurationError(
            "Expected --evidence-dir to be the bundle root or its evidence/ folder; "
            "the bundle root must contain evidence_files.csv."
        )
    missing = [name for name in REQUIRED_BUNDLE_FILES if not (bundle / name).is_file()]
    if missing:
        raise ConfigurationError(f"Evidence bundle is missing required files: {', '.join(missing)}")
    return bundle


def validate_request_path(requests_path: Path) -> Path:
    path = requests_path.expanduser().resolve()
    if not path.is_file():
        raise ConfigurationError(f"Request CSV does not exist or is not a file: {path}")
    return path


def validate_manifest_paths(bundle_dir: Path, manifest_rows: list[dict[str, str]]) -> None:
    """Reject manifest paths escaping the supplied local bundle directory."""
    root = bundle_dir.resolve()
    for row in manifest_rows:
        rel = Path(row.get("file_path", ""))
        candidate = (root / rel).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ConfigurationError("Evidence manifest contains a path outside the bundle directory") from exc
