"""Small public models for configuration and completed audit runs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class AuditConfig:
    """Explicit filesystem inputs for one local audit run."""

    requests_path: Path
    bundle_dir: Path
    output_path: Path
    diagnostics_path: Path | None = None


@dataclass(frozen=True)
class AuditRunSummary:
    """Non-sensitive summary returned by :func:`run_audit`."""

    request_count: int
    output_path: Path
    status_counts: Mapping[str, int]
