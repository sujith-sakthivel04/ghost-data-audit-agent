"""Public package API around the behavior-preserved reference engine.

The private module contains the audited parser and policy implementation. This
module supplies reusable, explicit-path entry points without running an audit
when imported.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from . import _challenge_engine as _core
from .config import ConfigurationError, validate_manifest_paths, validate_request_path
from .models import AuditConfig, AuditRunSummary

# Preserve the tested low-level API for integrations and synthetic regression tests.
for _name in dir(_core):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_core, _name)

logger = logging.getLogger("ghost_audit")

ALLOWED_PAIRS = {
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}
STEP_KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}


def _validate_request_rows(rows: list[dict[str, str]]) -> None:
    required = {"case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"}
    if not rows:
        raise ConfigurationError("Request CSV contains no data rows")
    if not required.issubset(rows[0]):
        missing = sorted(required - set(rows[0]))
        raise ConfigurationError(f"Request CSV is missing required columns: {', '.join(missing)}")
    ids = [row.get("case_id", "") for row in rows]
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        raise ConfigurationError("Request CSV must have non-empty, unique case_id values")


def _validate_steps(rows: list[dict[str, str]], requests: list[dict[str, str]]) -> list[str]:
    issues: list[str] = []
    expected = {r["case_id"] for r in requests}
    ids = [r.get("case_id", "") for r in rows]
    if len(rows) != len(expected):
        issues.append(f"Expected {len(expected)} output rows, found {len(rows)}")
    if len(ids) != len(set(ids)):
        issues.append("Output contains duplicate case_id values")
    if set(ids) != expected:
        issues.append("Output case_id coverage differs from request CSV")
    expected_order = sorted(ids, key=lambda value: int(value.rsplit("_", 1)[-1])
                            if value.rsplit("_", 1)[-1].isdigit() else value)
    if ids != expected_order:
        issues.append("Output rows are not in numeric case_id order")
    req_by_id = {r["case_id"]: r for r in requests}
    for row_no, row in enumerate(rows, 2):
        status = row.get("deletion_status")
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            issues.append(f"Row {row_no}: invalid deletion_status")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except (TypeError, json.JSONDecodeError):
            issues.append(f"Row {row_no}: invalid steps_json")
            continue
        if not isinstance(steps, list):
            issues.append(f"Row {row_no}: steps_json must be an array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            issues.append(f"Row {row_no}: NOT_APPLICABLE must have an empty array")
        if status == "COMPLETE" and any(not isinstance(s, dict) or s.get("phase") != "VERIFICATION" for s in steps):
            issues.append(f"Row {row_no}: COMPLETE may contain verification steps only")
        if row.get("case_id") not in req_by_id:
            continue
        cutoff = _core.parse_time(req_by_id[row["case_id"]].get("audit_at"))
        ordering = []
        for number, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                issues.append(f"Row {row_no}: step {number} must be an object")
                continue
            if set(step) != STEP_KEYS:
                issues.append(f"Row {row_no}: step {number} has an invalid field set")
                continue
            if step.get("step_no") != number:
                issues.append(f"Row {row_no}: step numbering is not consecutive")
            phase, operation, state = step.get("phase"), step.get("operation"), step.get("state")
            if (phase, operation, state) not in ALLOWED_PAIRS:
                issues.append(f"Row {row_no}: step {number} has a disallowed operation/state pair")
            if phase not in _core.PHASE_RANK:
                issues.append(f"Row {row_no}: step {number} has an invalid phase")
            else:
                ordering.append((_core.PHASE_RANK[phase], _core.OPERATION_RANK[phase].get(operation, 99),
                                 step.get("system_id", ""), step.get("resource_id", "")))
            eid = step.get("evidence_id", "")
            if status == "INCOMPLETE" and phase in {"REMEDIATION", "VERIFICATION"} and eid:
                issues.append(f"Row {row_no}: future action must have an empty evidence_id")
            if (phase == "FINDING" or (status == "COMPLETE" and phase == "VERIFICATION")) and not eid:
                issues.append(f"Row {row_no}: finding/completed verification needs evidence")
        if ordering != sorted(ordering):
            issues.append(f"Row {row_no}: steps violate phase/operation/system/resource ordering")
    return issues


def validate_output_file(output_path: Path, requests_path: Path) -> list[str]:
    """Validate the output contract against an explicit request CSV."""
    output_path = output_path.expanduser().resolve()
    requests_path = validate_request_path(requests_path)
    try:
        requests = _core.read_csv(requests_path)
        rows = _core.read_csv(output_path)
        with output_path.open("r", encoding="utf-8-sig", newline="") as handle:
            header = next(csv.reader(handle), [])
    except (OSError, ValueError, csv.Error) as exc:
        return [f"Could not read validation input: {exc}"]
    issues = []
    if header != ["case_id", "deletion_status", "steps_json"]:
        issues.append("Output header must be case_id,deletion_status,steps_json")
    issues.extend(_validate_steps(rows, requests))
    return issues


def run_audit(config: AuditConfig) -> AuditRunSummary:
    """Run the baseline evidence engine against an explicitly selected bundle."""
    requests_path = validate_request_path(Path(config.requests_path))
    bundle_dir = Path(config.bundle_dir).expanduser().resolve()
    output_path = Path(config.output_path).expanduser().resolve()
    if not bundle_dir.is_dir():
        raise ConfigurationError(f"Bundle directory does not exist: {bundle_dir}")
    required_files = ("evidence_files.csv", "user_identities.csv", "user_audit_log.csv",
                      "system_activity.csv", "deletion_rules.csv")
    missing = [name for name in required_files if not (bundle_dir / name).is_file()]
    if missing:
        raise ConfigurationError(f"Bundle is missing required files: {', '.join(missing)}")
    if output_path == requests_path or output_path.is_relative_to(bundle_dir):
        raise ConfigurationError("Output path must not overwrite a request or evidence-bundle file")

    requests = _core.read_csv(requests_path)
    _validate_request_rows(requests)
    manifest = _core.read_csv(bundle_dir / "evidence_files.csv")
    validate_manifest_paths(bundle_dir, manifest)
    identities = _core.build_identity_maps(bundle_dir)
    activities = _core.load_activity(bundle_dir)
    logger.info("Loaded %d requests and %d activity events", len(requests), len(activities))
    index = _core.EvidenceIndex(bundle_dir)
    logger.info("Indexed %d observations across %d manifest files", len(index.observations), len(index.manifest))
    nearest = _core.assign_activity_nearest_case(requests, activities)
    activity_index = _core.ActivityRetrievalIndex(activities, nearest)
    outputs = [_core.build_case_output(r, requests, index, activities, identities, nearest, activity_index)
               for r in requests]
    outputs.sort(key=lambda row: int(row["case_id"].rsplit("_", 1)[-1])
                 if row["case_id"].rsplit("_", 1)[-1].isdigit() else row["case_id"])

    issues = _validate_steps(outputs, requests)
    if issues:
        raise RuntimeError("Generated output failed validation: " + "; ".join(issues[:5]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"],
                                    lineterminator="\n")
            writer.writeheader()
            writer.writerows(outputs)
        check = validate_output_file(Path(temporary_name), requests_path)
        if check:
            raise RuntimeError("Generated CSV failed validation: " + "; ".join(check[:5]))
        os.replace(temporary_name, output_path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise

    if config.diagnostics_path:
        diag = Path(config.diagnostics_path).expanduser().resolve()
        diag.parent.mkdir(parents=True, exist_ok=True)
        diag.write_text(json.dumps({"cases": index.diagnostics_by_case}, ensure_ascii=False, indent=2) + "\n",
                         encoding="utf-8")
    counts = Counter(row["deletion_status"] for row in outputs)
    logger.info("Wrote %d rows: %s", len(outputs), dict(counts))
    return AuditRunSummary(len(outputs), output_path, dict(sorted(counts.items())))


__all__ = ["AuditConfig", "AuditRunSummary", "run_audit", "validate_output_file"] + [
    name for name in dir(_core) if not name.startswith("_")
]
