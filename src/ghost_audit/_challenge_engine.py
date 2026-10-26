#!/usr/bin/env python3
"""Ghost Data Still Exists: evidence-grounded deletion audit.

The engine is deterministic by design. It indexes participant-facing evidence,
resolves current and historical identifiers, reconstructs resource state at each
audit cutoff, applies deletion rules, and emits the strict HackerRank CSV schema.

Optional PDF/image readers are used when installed. No network calls or model
API calls are made by default; therefore the default usage report records zero
LLM tokens and zero model cost.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import shutil
import subprocess
import sys
import unicodedata
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

RESOURCE_RE = re.compile(
    r"\b(?:account|search|support|export|analytics|email|cache|audit_record|"
    r"data_flow|backup|tombstone|legal|object|sessions|invoice|marketing)_[A-Za-z0-9-]*\d[A-Za-z0-9-]*\b",
    re.IGNORECASE,
)
# These strings are system identifiers, not resource IDs, despite resembling the
# resource prefix pattern. Keeping them out prevents false resources such as
# ``search_service`` or ``analytics_platform`` from entering the audit graph.
NON_RESOURCE_IDS = {
    "account_service", "search_service", "support_platform", "export_service",
    "analytics_platform", "email_delivery_service", "cache_service", "security_service",
    "integration_service", "backup_service", "identity_service", "legal_service",
    "object_store", "billing_service", "marketing_platform", "email_service",
    "support_service", "account_platform", "data_platform",
}

def is_resource_id(value: Any) -> bool:
    rid = str(value or "").strip()
    return bool(RESOURCE_RE.fullmatch(rid)) and rid.casefold() not in NON_RESOURCE_IDS

def extract_resource_ids(text: Any) -> list[str]:
    return [rid for rid in dict.fromkeys(RESOURCE_RE.findall(str(text or ""))) if is_resource_id(rid)]


def resource_id_from_fields(fields: dict[str, Any]) -> str:
    """Resolve an explicitly named resource key across common field spellings."""
    preferred = {"resourceid", "resourceidentifier", "resource", "id"}
    for key, value in fields.items():
        normalized = str(key or "").casefold().replace("_", "").replace("-", "")
        if normalized not in preferred:
            continue
        candidate = str(value or "").strip()
        if is_resource_id(candidate):
            return candidate
    return ""


EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
TIME_RE = re.compile(
    r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?\b"
)
HUMAN_TIME_RE = re.compile(
    r"(?<!\d)(\d{1,2}\s+[A-Za-z]{3}\s+20\d{2}\s+\d{2}:\d{2}(?::\d{2})?)"
    r"\s*(UTC|GMT|JST|KST|Z|[+-]\d{2}:?\d{2})(?![A-Za-z0-9])",
    re.I,
)
_OCR_TEXT_CACHE: OrderedDict[tuple[str, str, int, int, str], str] = OrderedDict()
_OCR_TEXT_CACHE_LIMIT = 32

# The ordering of these maps is part of the output contract.
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_RANK = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": 0,
        "REPORT_EXPOSED_PII": 1,
        "REPORT_ACTIVE_DATA_FLOW": 2,
        "REPORT_RESTORE_RISK": 3,
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": 0,
        "BLOCK_RESTORE": 1,
        "DELETE_RECORD": 2,
        "REDACT_RECORD": 3,
        "ANONYMIZE_RECORD": 4,
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": 0,
        "VERIFY_RECORD_PRESENT": 1,
        "VERIFY_RECORD_REDACTED": 2,
        "VERIFY_RECORD_ANONYMIZED": 3,
        "VERIFY_DATA_FLOW_DISABLED": 4,
        "VERIFY_RESTORE_BLOCKED": 5,
    },
}

SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "search": "search_service",
    "support": "support_platform",
    "export": "export_service",
    "analytics": "analytics_platform",
    "email": "email_delivery_service",
    "cache": "cache_service",
    "audit_record": "security_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "tombstone": "identity_service",
    "legal": "legal_service",
    "object": "object_store",
    "sessions": "analytics_platform",
    "invoice": "billing_service",
    "marketing": "marketing_platform",
}

IDENTITY_KEYS = {
    "email", "owner_email", "customer_email", "requester_email", "lookup_key",
    "correlation_key", "match_key", "email_hash", "phone", "owner_phone",
    "requester_phone", "full_name", "display_name", "name", "customer_name",
    "requester_name", "subject_reference", "customer_reference", "user_id",
    "user_ref", "subject_ref", "subject_reference", "subject_selector", "subject_key", "subject_ref", "email_address",
}

_LOOKUP_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+|"
    r"user_[A-Za-z0-9-]+|[A-Fa-f0-9]{32,})(?![A-Za-z0-9_])",
    re.I,
)


class _TextMatchIndex:
    """Lossless candidate superset index for the existing alias matcher."""

    def __init__(self, items: list[Any], text_values):
        self.by_exact: dict[str, list[Any]] = defaultdict(list)
        self.by_normalized: dict[str, list[Any]] = defaultdict(list)
        self.by_token: dict[str, list[Any]] = defaultdict(list)
        self.by_digits: dict[str, list[Any]] = defaultdict(list)
        self.order = {id(item): pos for pos, item in enumerate(items)}
        for item in items:
            normalized: set[str] = set()
            exact: set[str] = set()
            tokens: set[str] = set()
            digit_values: set[str] = set()
            for raw_value in text_values(item):
                if raw_value is None:
                    continue
                value = str(raw_value).strip()
                if not value:
                    continue
                exact.add(value.casefold())
                norm = norm_text(value)
                if norm:
                    normalized.add(norm)
                digit_value = digits(value)
                if len(digit_value) >= 8:
                    digit_values.add(digit_value)
                for match in _LOOKUP_TOKEN_RE.finditer(value):
                    token = match.group(0).rstrip(".,;:!?").casefold()
                    if token:
                        tokens.add(token)
            for key in normalized:
                self.by_normalized[key].append(item)
            for key in exact:
                self.by_exact[key].append(item)
            for key in tokens:
                self.by_token[key].append(item)
            for key in digit_values:
                self.by_digits[key].append(item)

    def lookup(self, aliases: set[str], normalized_aliases: set[str]) -> list[Any]:
        found: dict[int, Any] = {}
        for alias in aliases:
            for item in self.by_exact.get(str(alias).strip().casefold(), ()):
                found[id(item)] = item
        for key in normalized_aliases:
            for item in self.by_normalized.get(key, ()):
                found[id(item)] = item
        for alias in aliases:
            key = str(alias).strip().casefold()
            if not key:
                continue
            if "@" in key or key.startswith("user_") or re.fullmatch(r"[a-f0-9]{32,}", key):
                for item in self.by_token.get(key, ()):
                    found[id(item)] = item
            phone_key = digits(key)
            if len(phone_key) >= 8:
                for item in self.by_digits.get(phone_key, ()):
                    found[id(item)] = item
        return sorted(found.values(), key=lambda item: self.order[id(item)])

@dataclass
class Observation:
    file_id: str
    file_path: str
    captured_at: datetime
    observed_at: datetime
    resource_id: str
    system_id: str
    fields: dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    record_kind: str = "record"
    explicit_state: str = ""  # ABSENT, PRESENT, REDACTED, ANONYMIZED, DISABLED, BLOCKED
    linked: bool = False
    timestamp_mentions: list[tuple[str, datetime]] = field(default_factory=list)
    timestamp_warnings: list[str] = field(default_factory=list)

@dataclass
class Activity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str
    # Parsed once when activities are loaded, then reused safely across requests.
    # None preserves compatibility for caller-created Activity instances.
    identity_fields: Optional[dict[str, list[str]]] = None

@dataclass
class Candidate:
    resource_id: str
    system_id: str
    category: str
    observations: list[Observation] = field(default_factory=list)
    related_by_activity: list[Activity] = field(default_factory=list)
    direct_match: bool = False
    association_reasons: list[str] = field(default_factory=list)
    related_document_ids: list[str] = field(default_factory=list)


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def extract_timestamp_mentions(text: Any) -> list[tuple[str, datetime]]:
    """Return explicitly zoned timestamps while retaining their source strings."""
    source = str(text or "")
    mentions: list[tuple[str, datetime]] = []
    seen: set[tuple[str, str]] = set()
    for match in TIME_RE.finditer(source):
        raw = match.group(0)
        parsed = parse_time(raw)
        if parsed:
            key = (raw, parsed.isoformat())
            if key not in seen:
                seen.add(key)
                mentions.append((raw, parsed))
    offsets = {"UTC": "+00:00", "GMT": "+00:00", "Z": "+00:00", "JST": "+09:00", "KST": "+09:00"}
    for match in HUMAN_TIME_RE.finditer(source):
        raw_date, zone = match.group(1), match.group(2).upper()
        if zone in offsets:
            zone_text = offsets[zone]
        else:
            zone_text = zone if ":" in zone or len(zone) == 6 else zone[:3] + ":" + zone[3:]
        raw = match.group(0)
        try:
            fmt = "%d %b %Y %H:%M:%S" if raw_date.count(":") == 2 else "%d %b %Y %H:%M"
            naive = datetime.strptime(raw_date, fmt)
            tzinfo = datetime.fromisoformat("2000-01-01T00:00:00" + zone_text).tzinfo
            parsed = naive.replace(tzinfo=tzinfo)
        except ValueError:
            continue
        key = (raw, parsed.isoformat())
        if key not in seen:
            seen.add(key)
            mentions.append((raw, parsed))
    return mentions


def timestamp_is_validity_bound(text: str, raw_timestamp: str, fields: dict[str, Any]) -> bool:
    """Do not flag future expiry/retention bounds as events after a snapshot capture."""
    validity_keys = ("expires", "expiry", "retention_until", "valid_to", "valid_until")
    for key, value in fields.items():
        key_name = str(key).lower().split(".")[-1]
        if any(token in key_name for token in validity_keys) and str(value or "").strip() == raw_timestamp:
            return True
    for match in re.finditer(re.escape(raw_timestamp), text or "", re.I):
        prefix = (text or "")[max(0, match.start() - 70):match.start()].casefold()
        if re.search(r"(?:expir\w*|retention\s+end|valid\s+(?:to|until|through))[^\n]{0,50}$", prefix):
            return True
    return False


def norm_text(value: Any) -> str:
    s = unicodedata.normalize("NFKD", str(value or "")).casefold()
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.replace("’", "'").replace("‘", "'")
    return re.sub(r"[^a-z0-9@.+_-]+", " ", s).strip()


def digits(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def infer_system(resource_id: str, context: str = "") -> str:
    rid = (resource_id or "").lower()
    # Longest prefixes first (e.g. data_flow before data).
    for prefix in sorted(SYSTEM_BY_PREFIX, key=len, reverse=True):
        if rid.startswith(prefix + "_"):
            return SYSTEM_BY_PREFIX[prefix]
    c = context.lower()
    for token, sysid in [
        ("account", "account_service"), ("search", "search_service"),
        ("support", "support_platform"), ("export", "export_service"),
        ("analytics", "analytics_platform"), ("backup", "backup_service"),
        ("security", "security_service"), ("integration", "integration_service"),
        ("identity", "identity_service"), ("marketing", "marketing_platform"),
        ("cache", "cache_service"), ("legal", "legal_service"),
        ("email_delivery", "email_delivery_service"),
    ]:
        if token in c:
            return sysid
    return "unknown_system"


def flatten_scalars(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(flatten_scalars(v, key))
            else:
                out[key] = v
                out[str(k)] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                out.update(flatten_scalars(v, f"{prefix}[{i}]"))
            else:
                out[f"{prefix}[{i}]"] = v
    return out


def scalar_value(fields: dict[str, Any], *names: str) -> str:
    lower_map = {str(k).lower(): v for k, v in fields.items()}
    for name in names:
        for k, v in lower_map.items():
            if k == name.lower() or k.endswith("." + name.lower()):
                if v is not None:
                    return str(v)
    return ""


def status_from(fields: dict[str, Any], raw: str, record_kind: str = "record") -> str:
    f = {str(k).lower().split(".")[-1]: v for k, v in fields.items()}
    text = (raw or "").casefold()
    # Explicit readback / lookup miss is a negative observation.
    code = str(f.get("status_code", f.get("http_status", ""))).strip()
    rows = str(f.get("rows", f.get("total_hits", f.get("total", "")))).strip()
    result = str(f.get("result", "")).casefold()
    if code in {"404", "410"} or rows == "0" or result in {"miss", "not_found", "not found", "absent"}:
        if "status" not in f or str(f.get("status", "")).upper() not in {"ACTIVE", "DELETED"}:
            return "ABSENT"
    if re.search(r"\bNOT_FOUND\b|\bNOT FOUND\b|rows\s*=\s*0|http_status\s*=\s*404|status_code\s*[:=]\s*404", raw, re.I):
        return "ABSENT"
    # Explicit policy outcomes in handover reports and readback traces.
    for val, state in [
        ("ANONYMIZED", "ANONYMIZED"), ("ANONYMIZED", "ANONYMIZED"),
        ("REDACTED", "REDACTED"), ("BLOCKED", "BLOCKED"),
        ("DISABLED", "DISABLED"),
    ]:
        if val in str(f.get("status", "")).upper() or re.search(rf"\b{val}\b", raw, re.I):
            return state
    if "restore_allowed" in f and str(f.get("restore_allowed")).lower() in {"0", "false", "no"}:
        return "BLOCKED"
    if "enabled" in f and str(f.get("enabled")).lower() in {"0", "false", "no"}:
        return "DISABLED"
    if "download_available" in f and str(f.get("download_available")).lower() in {"0", "false", "no"}:
        return "ABSENT"
    if "IDENTIFIABLE" in str(f.get("status", "")).upper() or re.search(r"\bIDENTIFIABLE\b", raw, re.I):
        return "PRESENT"
    if "FOUND" in str(f.get("status", "")).upper() or re.search(r"\bFOUND\b|result\s*=\s*hit", raw, re.I):
        return "PRESENT"
    if "enabled" in f and str(f.get("enabled")).lower() in {"1", "true", "yes"}:
        return "ACTIVE"
    if "restore_allowed" in f and str(f.get("restore_allowed")).lower() in {"1", "true", "yes"}:
        return "ACTIVE"
    if str(f.get("eligible", "")).lower() in {"1", "true", "yes"} and str(f.get("deletion_block", "")).lower() in {"0", "false", "no"}:
        return "ACTIVE"
    return "PRESENT"


def candidate_category(resource_id: str, system_id: str, fields: dict[str, Any], raw_text: str, file_path: str) -> str:
    rid = (resource_id or "").lower()
    raw = (raw_text or "").upper()
    allvals = " ".join(str(v) for v in fields.values() if v is not None).upper() + " " + raw
    f = {str(k).lower().split(".")[-1]: v for k, v in fields.items()}
    # A persisted correlation key that is a long hexadecimal hash is a secondary
    # identifier, not an analytics cohort to be retained after anonymization.
    corr = str(f.get("correlation_key") or "").strip()
    if corr and re.fullmatch(r"[0-9a-f]{32,}", corr, re.I):
        return "SECONDARY_IDENTIFIER"
    # Legacy support contact indexes are identity lookup artifacts, not conversations.
    if "LEGACY_CONTACT_INDEX" in allvals or "SUPPORT_REPLICA" in str(file_path).upper() and "SUPPORT_" in rid.upper():
        return "SECONDARY_IDENTIFIER"
    if rid.startswith("account_") or system_id == "account_service":
        return "USER_PROFILE"
    if rid.startswith("search_") or system_id == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if rid.startswith("cache_") or system_id == "cache_service":
        return "CACHE_ENTRY"
    if rid.startswith("support_") or system_id == "support_platform":
        if "SUPPORT_ATTACHMENT" in allvals or "ATTACHMENT" in Path(file_path).name.upper() or str(file_path).lower().endswith(".pdf"):
            return "SUPPORT_ATTACHMENT"
        if "ATTACHMENT" in allvals and "MESSAGE" not in allvals:
            return "SUPPORT_ATTACHMENT"
        return "SUPPORT_MESSAGE"
    if rid.startswith("export_") or system_id == "export_service":
        return "USER_EXPORT"
    if rid.startswith("analytics_") or rid.startswith("sessions_") or system_id == "analytics_platform":
        if "TELEMETRY" in allvals or rid.startswith("sessions_"):
            return "PRODUCT_TELEMETRY"
        return "ANALYTICS_PROFILE"
    if rid.startswith("email_") or system_id == "email_delivery_service":
        return "EMAIL_DELIVERY_LOG"
    if rid.startswith("data_flow_") or system_id == "integration_service":
        return "DATA_FLOW"
    if rid.startswith("backup_") or system_id == "backup_service":
        return "BACKUP_ARCHIVE"
    if rid.startswith("audit_record_") or system_id == "security_service":
        return "SECURITY_AUDIT_LOG"
    if rid.startswith("tombstone_") or system_id == "identity_service":
        return "ACCOUNT_TOMBSTONE"
    if rid.startswith("legal_") or system_id == "legal_service":
        return "LEGAL_HOLD_RECORD"
    if rid.startswith("object_") or system_id in {"object_store", "object_storage"}:
        return "SUPPORT_ATTACHMENT"
    if rid.startswith("marketing_") or system_id == "marketing_platform":
        return "MARKETING_PROFILE"
    if "SECONDARY_IDENTIFIER" in allvals:
        return "SECONDARY_IDENTIFIER"
    return "UNKNOWN"


def fields_have_direct_pii(fields: dict[str, Any], raw: str = "") -> bool:
    direct_keys = {
        "email", "owner_email", "customer_email", "requester_email", "email_address",
        "email_hash", "phone", "owner_phone", "requester_phone", "full_name",
        "display_name", "name", "requester_name", "customer_name",
    }
    for key, value in fields.items():
        if str(key).lower().split(".")[-1] in direct_keys and value not in (None, "", "null", "NULL", "[REDACTED]"):
            return True
    return False


def field_is_present(value: Any) -> bool:
    return value not in (None, "", "null", "NULL", "[REDACTED]", "REDACTED")


def find_tesseract_executable() -> str:
    """Find a working local Tesseract binary, including common paths outside PATH."""
    candidates: list[str] = []
    configured = os.environ.get("TESSERACT_CMD", "").strip().strip('"')
    if configured:
        configured_path = Path(configured).expanduser()
        if configured_path.is_file():
            candidates.append(str(configured_path))
        else:
            located = shutil.which(configured)
            if located:
                candidates.append(located)
    located = shutil.which("tesseract")
    if located:
        candidates.append(located)

    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                     os.environ.get("LOCALAPPDATA")):
            if base:
                folder = "Programs\\Tesseract-OCR" if base == os.environ.get("LOCALAPPDATA") else "Tesseract-OCR"
                candidates.append(str(Path(base) / folder / "tesseract.exe"))
    else:
        candidates.extend(("/usr/bin/tesseract", "/usr/local/bin/tesseract", "/opt/homebrew/bin/tesseract"))

    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(os.path.abspath(candidate))
        if key in seen:
            continue
        seen.add(key)
        if not Path(candidate).is_file():
            continue
        try:
            proc = subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
            if proc.returncode == 0:
                return candidate
        except Exception:
            continue
    return ""


class EvidenceIndex:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.manifest = read_csv(dataset_dir / "evidence_files.csv")
        self.observations: list[Observation] = []
        self.by_resource: dict[str, list[Observation]] = defaultdict(list)
        self.document_texts: list[tuple[str, str, datetime, str]] = []
        self.snapshot_coverage: list[tuple[str, str, datetime, str]] = []  # system, file_id, capture time, table
        self._ocr_engine_checked = False
        self._ocr_engine_available = False
        self._ocr_command_checked = False
        self._ocr_command = ""
        self.diagnostics_by_case: dict[str, dict[str, Any]] = {}
        self._load_all()

    def _add(self, obs: Observation) -> None:
        if not obs.timestamp_mentions:
            obs.timestamp_mentions.extend(extract_timestamp_mentions(obs.raw_text))
        for key, value in obs.fields.items():
            key_name = str(key).lower().split(".")[-1]
            if not any(token in key_name for token in ("time", "date", "created", "updated", "expiry", "expires", "retention", "valid")):
                continue
            if value in (None, ""):
                continue
            raw = str(value).strip()
            parsed = parse_time(raw)
            if parsed:
                if not any(existing_raw == raw for existing_raw, _ in obs.timestamp_mentions):
                    obs.timestamp_mentions.append((raw, parsed))
                if re.fullmatch(r"20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?", raw):
                    warning = f"timestamp has no timezone; interpreted as UTC: {raw}"
                    if warning not in obs.timestamp_warnings:
                        obs.timestamp_warnings.append(warning)
            elif re.search(r"\d{4}-\d{2}-\d{2}|\d{1,2}\s+[A-Za-z]{3}\s+20\d{2}", raw):
                warning = f"unparsed timestamp field {key}={raw}"
                if warning not in obs.timestamp_warnings:
                    obs.timestamp_warnings.append(warning)
        for raw, parsed in obs.timestamp_mentions:
            if parsed > obs.captured_at and not timestamp_is_validity_bound(obs.raw_text, raw, obs.fields):
                warning = f"embedded timestamp after capture: {raw}"
                if warning not in obs.timestamp_warnings:
                    obs.timestamp_warnings.append(warning)
        self.observations.append(obs)
        self.by_resource[obs.resource_id].append(obs)

    def _load_all(self) -> None:
        for mf in self.manifest:
            file_id = mf["file_id"]
            rel = mf["file_path"]
            path = self.dataset_dir / rel
            captured = parse_time(mf.get("captured_at"))
            if not path.exists() or not captured:
                continue
            ext = path.suffix.lower()
            try:
                if ext == ".json":
                    obj = json.loads(read_text(path))
                    self._parse_json(file_id, rel, captured, obj)
                elif ext == ".csv":
                    self._parse_csv(file_id, rel, captured, path)
                elif ext == ".sql":
                    self._parse_sql(file_id, rel, captured, path)
                elif ext in {".log", ".txt"}:
                    self._parse_text(file_id, rel, captured, read_text(path), whole_document=False)
                elif ext == ".pdf":
                    txt = self._pdf_text(path)
                    if txt:
                        self.document_texts.append((file_id, rel, captured, txt))
                    self._parse_text(file_id, rel, captured, txt, whole_document=True)
                elif ext in {".png", ".jpg", ".jpeg", ".webp"}:
                    txt = self._image_text(path)
                    if txt:
                        self.document_texts.append((file_id, rel, captured, txt))
                    self._parse_text(file_id, rel, captured, txt, whole_document=True)
                else:
                    continue
            except Exception as exc:  # robust ingestion: a bad evidence file must not stop all cases
                print(f"[warn] Could not parse {rel}: {exc}", file=sys.stderr)

        # Deduplicate exact duplicate observations produced by nested structured payloads.
        seen = set()
        deduped: list[Observation] = []
        by_resource: dict[str, list[Observation]] = defaultdict(list)
        for o in self.observations:
            sig = (o.file_id, o.resource_id, o.system_id, o.observed_at.isoformat(), json.dumps(o.fields, sort_keys=True, default=str), o.explicit_state)
            if sig in seen:
                continue
            seen.add(sig)
            deduped.append(o)
            by_resource[o.resource_id].append(o)
        self.observations = deduped
        self.by_resource = by_resource
        # Immutable retrieval postings are scoped to this evidence bundle and audit.
        self._identity_search = _TextMatchIndex(
            self.observations,
            lambda obs: [*obs.fields.values(), obs.raw_text],
        )

    def identity_candidates(self, aliases: set[str], normalized_aliases: set[str]) -> list[Observation]:
        """Return an ordered superset; callers still apply exact identity and cutoff checks."""
        return self._identity_search.lookup(aliases, normalized_aliases)

    def _pdf_text(self, path: Path) -> str:
        try:
            from pypdf import PdfReader  # type: ignore
            reader = PdfReader(str(path))
            return "\n\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception:
            try:
                proc = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, timeout=20)
                if proc.returncode == 0:
                    return proc.stdout
            except Exception:
                pass
        return ""


    def _image_text(self, path: Path) -> str:
        """Extract screenshot text with bounded, local-only OCR when available."""
        if path.suffix.lower() not in {".png", ".jpg", ".jpeg"}:
            return ""
        try:
            if path.stat().st_size > 20 * 1024 * 1024:
                return ""
            from PIL import Image, ImageOps  # type: ignore
        except Exception:
            return ""

        try:
            with Image.open(path) as source:
                if (source.format or "").upper() not in {"PNG", "JPEG"}:
                    return ""
                width, height = source.size
                if width <= 0 or height <= 0 or width * height > 24_000_000:
                    return ""
                source.load()
                image = ImageOps.exif_transpose(source).convert("L")
                width, height = image.size
                longest = max(width, height)
                if longest > 4000:
                    scale = 4000 / longest
                    image = image.resize((max(1, round(width * scale)), max(1, round(height * scale))))
                elif longest < 1600:
                    scale = min(2.0, 2400 / longest)
                    image = image.resize((round(width * scale), round(height * scale)))
                encoded = io.BytesIO()
                image.save(encoded, format="PNG")
                image_bytes = encoded.getvalue()
        except Exception:
            return ""

        # Resolve and validate the local executable once per evidence index. An
        # override and common install paths allow binaries omitted from PATH.
        if not self._ocr_command_checked:
            self._ocr_command = find_tesseract_executable()
            self._ocr_command_checked = True
            if self._ocr_command:
                try:
                    import pytesseract  # type: ignore
                    pytesseract.pytesseract.tesseract_cmd = self._ocr_command
                    pytesseract.get_tesseract_version()
                    self._ocr_engine_available = True
                except Exception:
                    self._ocr_engine_available = False
            self._ocr_engine_checked = True

        if self._ocr_engine_available:
            try:
                stat = path.stat()
                digest = hashlib.sha256(image_bytes).hexdigest()
                cache_key = (str(path.resolve()), digest, stat.st_mtime_ns, stat.st_size, self._ocr_command)
                cached = _OCR_TEXT_CACHE.get(cache_key)
                if cached is not None:
                    _OCR_TEXT_CACHE.move_to_end(cache_key)
                    return cached
            except OSError:
                cache_key = None
            try:
                import pytesseract  # type: ignore
                # Sparse UI layouts benefit from Tesseract's sparse-text mode: it
                # preserves row labels and identifiers that PSM 6 may merge.
                text = pytesseract.image_to_string(image, config="--psm 11", timeout=12).strip()
                if text and cache_key is not None:
                    _OCR_TEXT_CACHE[cache_key] = text
                    _OCR_TEXT_CACHE.move_to_end(cache_key)
                    while len(_OCR_TEXT_CACHE) > _OCR_TEXT_CACHE_LIMIT:
                        _OCR_TEXT_CACHE.popitem(last=False)
                return text
            except Exception:
                pass
        if self._ocr_command:
            try:
                proc = subprocess.run(
                    [self._ocr_command, "stdin", "stdout", "--psm", "11"],
                    input=image_bytes, capture_output=True, timeout=12,
                )
                return proc.stdout.decode("utf-8", errors="replace").strip() if proc.returncode == 0 else ""
            except Exception:
                pass
        return ""


    def _parse_json(self, file_id: str, rel: str, captured: datetime, root: Any) -> None:
        def walk(node: Any, context: list[str], inherited_time: Optional[datetime] = None) -> None:
            if isinstance(node, dict):
                local_time = inherited_time
                for time_key in ("captured_at", "observed_at", "exported_at", "snapshot_time", "read_at"):
                    if node.get(time_key):
                        parsed = parse_time(node.get(time_key))
                        if parsed:
                            local_time = parsed
                            break
                rid = resource_id_from_fields(node)
                fields = flatten_scalars(node)
                if rid and is_resource_id(rid):
                    sysid = infer_system(rid, " ".join(context + list(node.keys())))
                    raw = json.dumps(node, ensure_ascii=False, sort_keys=True, default=str)
                    kind = "lookup" if any(k in node for k in ("status_code", "http_status", "profile", "hits")) else "record"
                    state = status_from(fields, raw, kind)
                    obs_time = local_time or captured
                    self._add(Observation(file_id, rel, captured, obs_time, rid, sysid, fields, raw, kind, state))
                for k, v in node.items():
                    if isinstance(v, (dict, list)):
                        walk(v, context + [str(k)], local_time)
            elif isinstance(node, list):
                for v in node:
                    walk(v, context, inherited_time)
        walk(root, [])

    def _parse_csv(self, file_id: str, rel: str, captured: datetime, path: Path) -> None:
        """Index evidence CSV rows by explicit resource keys and retain row provenance."""
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            for row_no, row in enumerate(reader, 2):
                fields: dict[str, Any] = dict(row)
                rid = resource_id_from_fields(fields)
                if not rid:
                    continue
                system_id = str(row.get("system_id") or row.get("system") or "").strip()
                if not system_id:
                    system_id = infer_system(rid, rel)
                observed_at = captured
                for key, value in row.items():
                    if str(key or "").casefold() in {"observed_at", "event_time", "timestamp", "captured_at", "updated_at"}:
                        parsed = parse_time(value)
                        if parsed:
                            observed_at = parsed
                            break
                raw = json.dumps({"row_number": row_no, **fields}, ensure_ascii=False, sort_keys=True)
                self._add(Observation(file_id, rel, captured, observed_at, rid, system_id,
                                      fields, raw, "csv_record", status_from(fields, raw, "csv_record")))

    def _parse_sql(self, file_id: str, rel: str, captured: datetime, path: Path) -> None:
        # Execute SQLite-compatible snapshot in an isolated in-memory database.
        con = sqlite3.connect(":memory:")
        try:
            con.executescript(read_text(path))
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                info = con.execute(f'PRAGMA table_info("{table}")').fetchall()
                cols = [r[1] for r in info]
                rows = con.execute(f'SELECT * FROM "{table}"').fetchall()
                if table.lower() == "snapshot_scope":
                    for row in rows:
                        d = dict(zip(cols, row))
                        sysid = str(d.get("origin_system") or "unknown_system")
                        self.snapshot_coverage.append((sysid, file_id, captured, table))
                    continue
                for row in rows:
                    d = dict(zip(cols, row))
                    # Some SQLite-compatible exports store the actual record as a JSON
                    # string inside columns such as record_json or payload. Parse those
                    # payloads and expose nested scalar fields to identity/policy checks.
                    for column, value in list(d.items()):
                        if not isinstance(value, str):
                            continue
                        candidate_text = value.strip()
                        if not candidate_text or candidate_text[0] not in "{[":
                            continue
                        try:
                            nested = json.loads(candidate_text)
                        except (json.JSONDecodeError, TypeError):
                            continue
                        nested_fields = flatten_scalars(nested)
                        for nested_key, nested_value in nested_fields.items():
                            # Prefer top-level columns when names collide; add qualified
                            # copies too so nested provenance remains inspectable.
                            d.setdefault(nested_key, nested_value)
                            d[f"{column}.{nested_key}"] = nested_value
                    rid = resource_id_from_fields(d)
                    if not rid or not RESOURCE_RE.fullmatch(rid):
                        continue
                    sysid = infer_system(rid, table)
                    # The row's updated_at is record metadata; snapshot capture is observation time.
                    raw = f"TABLE {table}: " + json.dumps(d, ensure_ascii=False, sort_keys=True, default=str)
                    state = status_from(d, raw, "record")
                    self._add(Observation(file_id, rel, captured, captured, rid, sysid, d, raw, table, state))
                    self.snapshot_coverage.append((sysid, file_id, captured, table))
        finally:
            con.close()

    def _parse_text(self, file_id: str, rel: str, captured: datetime, text: str, whole_document: bool) -> None:
        if not text:
            return
        # PDFs/screenshots typically describe one artifact; split plain text/logs per line
        # to avoid accidentally linking a resource to another person's identifiers.
        if whole_document:
            ids = extract_resource_ids(text)
            if not ids:
                return
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            # A screenshot can show a table of unrelated records. Build each
            # observation from the resource's nearby row, never the full screen,
            # so one row's identifiers cannot bleed into another resource.
            compact = lambda value: re.sub(r"[^a-z0-9]", "", value.casefold())
            uid_values = set(re.findall(r"\buser_[A-Za-z0-9-]+\b", text, re.I))
            email_values = set(EMAIL_RE.findall(text))
            globally_scoped_identity = ""
            if len(uid_values) == 1:
                globally_scoped_identity = next(iter(uid_values))
            elif not uid_values and len(email_values) == 1:
                globally_scoped_identity = next(iter(email_values))
            for rid in ids:
                rid_key = compact(rid)
                anchors = [i for i, line in enumerate(lines) if rid_key in compact(line)]
                if anchors:
                    resource_lines = [i for i, line in enumerate(lines)
                                      if extract_resource_ids(line) or re.search(r"\bdata_flow\s+\d", line, re.I)]
                    selected = set()
                    for anchor in anchors:
                        # Treat the next resource label as a row boundary. OCR
                        # often puts each table cell on its own line, so include
                        # a bounded forward span but never the neighboring row.
                        later = [i for i in resource_lines if i > anchor]
                        span = 8 if rid.startswith("backup_") else 30
                        end = min(anchor + span, later[0] if later else len(lines))
                        selected.update(range(anchor, end))
                    scoped_text = "\n".join(line for i, line in enumerate(lines) if i in selected)
                else:
                    # OCR may split a token over lines; retain only a bounded
                    # character window around each exact resource occurrence.
                    matches = list(re.finditer(re.escape(rid), text, re.I))
                    scoped_text = "\n".join(text[max(0, m.start() - 180):m.end() + 260] for m in matches)
                if globally_scoped_identity and globally_scoped_identity.casefold() not in scoped_text.casefold():
                    if globally_scoped_identity.casefold().startswith("user_"):
                        scoped_text += "\nuser_id=" + globally_scoped_identity
                    else:
                        scoped_text += "\nemail=" + globally_scoped_identity
                # A backup console's selected-archive detail pane follows the
                # table. Bind it only to the last archive ID shown before that
                # pane's path header, so neighboring archive rows stay isolated.
                fields_retention = ""
                if rid.startswith("backup_"):
                    retention = re.search(r"Retention\s+end\s*:?\s*(\d{1,2} [A-Za-z]{3} 20\d{2})", text, re.I)
                    selected = re.search(r"Updated\s+moments\s+ago.{0,100}?(backup_[A-Za-z0-9-]*\d[A-Za-z0-9-]*)", text, re.I | re.S)
                    selected_rid = selected.group(1) if selected else ""
                    if retention and selected_rid.casefold() == rid.casefold():
                        detail_start = text.casefold().rfind(rid.casefold(), 0, retention.start())
                        detail = text[detail_start:]
                        activity_pos = re.search(r"\bActivity\b", detail, re.I)
                        if activity_pos:
                            detail = detail[:activity_pos.start()]
                        scoped_text += "\n" + detail
                        try:
                            retention_dt = datetime.strptime(retention.group(1), "%d %b %Y").replace(tzinfo=timezone.utc)
                            fields_retention = retention_dt.isoformat()
                        except ValueError:
                            fields_retention = ""
                fields = self._parse_kv_fields(scoped_text)
                fields["document_text"] = scoped_text
                if fields_retention:
                    fields["retention_until"] = fields_retention
                sysid = infer_system(rid, rel + " " + scoped_text[:100])
                state = status_from(fields, scoped_text, "document")
                self._add(Observation(file_id, rel, captured, self._text_time(scoped_text, captured), rid, sysid, fields, scoped_text, "document", state))
            return

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        parsed_lines = [(line, self._parse_kv_fields(line)) for line in lines]
        # Operational logs often put the subject/email on *_started and the resource ID
        # on *_completed. Carry identity-bearing fields across the same trace_id only.
        trace_context: dict[str, dict[str, str]] = defaultdict(dict)
        trace_identity_keys = IDENTITY_KEYS | {"subject_key", "subject_ref", "correlation_key", "match_key", "lookup_key", "customer_reference", "customer_ref"}
        for line, fields in parsed_lines:
            trace_id = str(fields.get("trace_id") or "").strip()
            if not trace_id:
                continue
            ctx = trace_context[trace_id]
            for key, value in fields.items():
                keytail = str(key).lower().split(".")[-1]
                val = str(value or "").strip()
                if keytail in trace_identity_keys and field_is_present(val) and val.lower() not in {"null", "none", "n/a"}:
                    if keytail in ctx and ctx[keytail] != val and val not in ctx[keytail].split(" | "):
                        ctx[keytail] += " | " + val
                    else:
                        ctx[keytail] = val
        for line, fields in parsed_lines:
            ids = extract_resource_ids(line)
            if not ids:
                continue
            # Delimited handover records have positional values instead of key=value fields.
            if "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 5:
                    fields.setdefault("system_id", parts[1])
                    fields.setdefault("resource_type", parts[3])
                    fields.setdefault("status", parts[4])
                    if len(parts) > 5:
                        fields.setdefault("identifier", parts[5])
            trace_id = str(fields.get("trace_id") or "").strip()
            if trace_id and trace_id in trace_context:
                for key, value in trace_context[trace_id].items():
                    if key not in fields or not field_is_present(fields.get(key)):
                        fields[key] = value
                    elif str(fields.get(key)) != value and value not in str(fields.get(key)).split(" | "):
                        fields[key] = str(fields.get(key)) + " | " + value
            obs_time = self._text_time(line, captured)
            state = status_from(fields, line, "line")
            for rid in ids:
                sysid = infer_system(rid, rel + " " + line + " " + str(fields.get("service", "")))
                self._add(Observation(file_id, rel, captured, obs_time, rid, sysid, fields.copy(), line, "line", state))

    @staticmethod
    def _text_time(text: str, default: datetime) -> datetime:
        m = TIME_RE.search(text or "")
        if not m:
            return default
        return parse_time(m.group(0)) or default

    @staticmethod
    def _parse_kv_fields(text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        # Structured service logs are timestamp-prefixed JSON. Parse that payload
        # first so trace_id, subject_ref, resource_id, enabled, eligible, and other
        # state-bearing fields are available to identity resolution and policy logic.
        brace = (text or "").find("{")
        if brace >= 0:
            payload = (text or "")[brace:].strip()
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    out.update(flatten_scalars(parsed))
            except (json.JSONDecodeError, TypeError):
                pass
        # Also support conventional key=value logs and handover text.
        pattern = re.compile(r'([A-Za-z_][A-Za-z0-9_.-]*)=("[^"]*"|\'[^\']*\'|[^\s,;]+)')
        for m in pattern.finditer(text or ""):
            v = m.group(2).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in {"'", '"'}:
                v = v[1:-1]
            out[m.group(1)] = v
        for email in EMAIL_RE.findall(text or ""):
            out.setdefault("email", email)
        for rid in extract_resource_ids(text or ""):
            out.setdefault("resource_id", rid)
        return out


ACTIVITY_IDENTITY_FIELD_KEYS = {
    "user_id", "user_ref", "user_reference", "subject_id", "subject_ref",
    "subject_reference", "customer_id", "customer_ref", "customer_reference",
    "email", "user_email", "subject_email", "customer_email", "requester_email",
    "phone", "user_phone", "subject_phone", "customer_phone", "requester_phone",
}
ACTIVITY_DETAIL_PAIR_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*([^\s,;|]+)")


def parse_activity_identity_fields(details: str) -> dict[str, list[str]]:
    """Parse only the keyed identity fields used by conflict checks."""
    keyed_values: dict[str, list[str]] = defaultdict(list)
    for match in ACTIVITY_DETAIL_PAIR_RE.finditer(details or ""):
        key = match.group(1).casefold()
        if key not in ACTIVITY_IDENTITY_FIELD_KEYS:
            continue
        value = match.group(2).strip(" '\"()[]{}")
        if value:
            keyed_values[key].append(value)
    return dict(keyed_values)


class ActivityRetrievalIndex:
    """Per-audit activity postings for identity, resource, and weak-case retrieval."""

    def __init__(self, activities: list[Activity], nearest_case_by_activity: dict[str, tuple[str, float]]):
        self.by_resource: dict[str, list[Activity]] = defaultdict(list)
        self.by_nearest_case: dict[str, list[Activity]] = defaultdict(list)
        for activity in activities:
            self.by_resource[activity.resource_id].append(activity)
            case_id = nearest_case_by_activity.get(activity.activity_id, ("", float("inf")))[0]
            if case_id:
                self.by_nearest_case[case_id].append(activity)
        self._identity_search = _TextMatchIndex(
            activities, lambda activity: [activity.details, activity.resource_id]
        )
        self._order = {id(activity): pos for pos, activity in enumerate(activities)}

    def candidates_for(self, case_id: str, linked_resource_ids: set[str], aliases: set[str],
                       normalized_aliases: set[str]) -> list[Activity]:
        found: dict[int, Activity] = {}
        for resource_id in linked_resource_ids:
            for activity in self.by_resource.get(resource_id, ()):
                found[id(activity)] = activity
        for activity in self.by_nearest_case.get(case_id, ()):
            found[id(activity)] = activity
        for activity in self._identity_search.lookup(aliases, normalized_aliases):
            found[id(activity)] = activity
        return sorted(found.values(), key=lambda activity: self._order[id(activity)])


def load_activity(dataset_dir: Path) -> list[Activity]:
    rows = read_csv(dataset_dir / "system_activity.csv")
    out = []
    for r in rows:
        tm = parse_time(r.get("event_time"))
        if not tm:
            continue
        details = r.get("details", "")
        out.append(Activity(r.get("activity_id", ""), tm, r.get("event_type", ""), r.get("source_system", ""), r.get("target_system", ""), r.get("resource_id", ""), r.get("reported_result", ""), details, parse_activity_identity_fields(details)))
    return out


def build_identity_maps(dataset_dir: Path):
    identities = read_csv(dataset_dir / "user_identities.csv")
    audits = read_csv(dataset_dir / "user_audit_log.csv")
    email_to_users: dict[str, set[str]] = defaultdict(set)
    user_current: dict[str, list[dict[str, str]]] = defaultdict(list)
    audit_by_user: dict[str, list[dict[str, str]]] = defaultdict(list)
    for u in identities:
        uid = u.get("user_id", "")
        if uid:
            user_current[uid].append(u)
            email = (u.get("email") or "").strip().casefold()
            if email:
                email_to_users[email].add(uid)
    for a in audits:
        uid = a.get("user_id", "")
        if uid:
            audit_by_user[uid].append(a)
        if (a.get("field_name") or "").casefold() == "email":
            for v in (a.get("old_value"), a.get("new_value")):
                if v:
                    email_to_users[v.strip().casefold()].add(uid)
    return identities, audits, email_to_users, user_current, audit_by_user


def resolve_identity(request: dict[str, str], maps, audit_at: datetime) -> tuple[str, set[str], set[str]]:
    identities, audits, email_to_users, user_current, audit_by_user = maps
    req_email = (request.get("email") or "").strip().casefold()
    ids = set(email_to_users.get(req_email, set()))
    # Honor the case cutoff for identity audit history when possible.
    eligible_ids = set()
    for a in audits:
        at = parse_time(a.get("event_time"))
        if not at or at > audit_at:
            continue
        if (a.get("field_name") or "").casefold() == "email" and req_email in {
            (a.get("old_value") or "").strip().casefold(),
            (a.get("new_value") or "").strip().casefold(),
        }:
            eligible_ids.add(a.get("user_id", ""))
    for uid, rows in user_current.items():
        for u in rows:
            updated = parse_time(u.get("updated_at"))
            if (u.get("email") or "").strip().casefold() == req_email and (not updated or updated <= audit_at):
                eligible_ids.add(uid)
    if eligible_ids:
        ids = eligible_ids
    # Use all-time mapping only as a last resort if the supplied current/audit snapshot is sparse.
    if not ids:
        ids = set(email_to_users.get(req_email, set()))
    uid = next(iter(ids)) if len(ids) == 1 else ""

    aliases: set[str] = {req_email} if req_email else set()
    normalized_aliases: set[str] = set()
    if uid:
        aliases.add(uid)
        for u in user_current.get(uid, []):
            updated = parse_time(u.get("updated_at"))
            if updated and updated > audit_at:
                continue
            for k in ("name", "email", "phone", "email_hash"):
                v = (u.get(k) or "").strip()
                if v:
                    aliases.add(v.casefold())
        identity_fields = {"email", "phone", "name", "full_name", "display_name", "email_hash", "phone_number", "mobile"}
        for a in audit_by_user.get(uid, []):
            at = parse_time(a.get("event_time"))
            if at and at > audit_at:
                continue
            if (a.get("field_name") or "").strip().casefold() not in identity_fields:
                continue
            for k in ("old_value", "new_value"):
                v = (a.get(k) or "").strip()
                if v:
                    aliases.add(v.casefold())
    normalized_aliases = {norm_text(a) for a in aliases if a and len(norm_text(a)) >= 3}
    return uid, aliases, normalized_aliases


def alias_occurs(value: Any, aliases: set[str], normalized_aliases: set[str], uid: str) -> bool:
    if value is None:
        return False
    s = str(value).strip()
    if not s:
        return False
    if s.casefold() in aliases:
        return True
    ns = norm_text(s)
    if ns in normalized_aliases:
        return True
    # Stable IDs, emails, and long hashes can be found as embedded values in log strings.
    for alias in aliases:
        a = alias.strip()
        if not a or len(a) < 6:
            continue
        if "@" in a or (a.startswith("user_") or re.fullmatch(r"[a-f0-9]{32,}", a)):
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(a)}(?![A-Za-z0-9_])", s, re.I):
                return True
    # Phone matching is by digit sequence to accommodate formatting differences.
    phone_digits = digits(s)
    if len(phone_digits) >= 8:
        for alias in aliases:
            ad = digits(alias)
            if len(ad) >= 8 and ad == phone_digits:
                return True
    # Do not match a shorter name as a substring of a longer name (e.g. Mateo Rios
    # must not match Mateo Rios Gil). Names match only when the normalized value is exact.
    return False


def observation_conflicts_user(obs: Observation, aliases: set[str], normalized_aliases: set[str], uid: str) -> bool:
    """Return True when explicit identity fields point to a different customer."""
    if not uid:
        return False
    f = {str(k).lower().split(".")[-1]: v for k, v in obs.fields.items()}
    # Stable user references take precedence over name similarity.
    for key in ("user_id", "subject_reference", "customer_reference", "subject_ref", "customer_ref", "user_ref", "user_reference", "subject_selector"):
        val = str(f.get(key) or "").strip()
        if val and re.fullmatch(r"user_[A-Za-z0-9-]+", val, re.I) and val.casefold() != uid.casefold():
            return True
    # A record with a populated direct email belonging to another identity is not linked
    # merely because its display name resembles the requested user's name.
    email_keys = {"email", "owner_email", "customer_email", "requester_email", "email_address"}
    emails = [str(v).strip().casefold() for k, v in f.items() if k in email_keys and field_is_present(v) and "@" in str(v)]
    if emails and not any(e in aliases for e in emails):
        return True
    phone_keys = {"phone", "owner_phone", "requester_phone", "mobile", "phone_number"}
    phones = [str(v).strip() for k, v in f.items() if k in phone_keys and field_is_present(v)]
    alias_phones = {digits(a) for a in aliases if len(digits(a)) >= 8}
    if phones and alias_phones and not any(digits(v) in alias_phones for v in phones if len(digits(v)) >= 8):
        return True
    return False


def obs_matches_user(obs: Observation, aliases: set[str], normalized_aliases: set[str], uid: str) -> bool:
    if observation_conflicts_user(obs, aliases, normalized_aliases, uid):
        return False
    # Exact identity-like values are the strongest link.
    for key, value in obs.fields.items():
        keytail = str(key).lower().split(".")[-1]
        if keytail in IDENTITY_KEYS or keytail in {"name", "full_name", "display_name"}:
            if alias_occurs(value, aliases, normalized_aliases, uid):
                return True
    # For logs/PDFs/OCR, use the record-scoped text (not the entire pack). Full names
    # must match exactly; embedded email/hash/user references remain valid anchors.
    return alias_occurs(obs.raw_text, aliases, normalized_aliases, uid)


def related_resource_ids(obs: Observation) -> set[str]:
    out = set()
    for key, value in obs.fields.items():
        k = str(key).lower().split(".")[-1]
        if k in {"source_resource_id", "parent_resource_id", "account_resource_id", "linked_resource_id", "related_resource_id", "resource_ids", "source_resources"}:
            for rid in extract_resource_ids(str(value or "")):
                if rid != obs.resource_id:
                    out.add(rid)
    return out


def explicit_reference_tokens(activity: Activity) -> list[str]:
    """Extract non-resource references explicitly parenthesized by a catalog link."""
    if activity.event_type != "LINK_RESOURCE_IDENTITY":
        return []
    tokens = []
    for match in re.finditer(r"\(([A-Za-z0-9][A-Za-z0-9._:/-]{5,})\)", activity.details):
        value = match.group(1)
        if is_resource_id(value) or EMAIL_RE.fullmatch(value):
            continue
        if value not in tokens:
            tokens.append(value)
    return tokens


def find_exact_reference_context(document_text: str, reference: str, aliases: set[str],
                                 normalized_aliases: set[str], uid: str) -> str:
    """Return a small source excerpt only when a unique exact key shares identity context."""
    pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(reference)}(?![A-Za-z0-9])", re.I)
    matches = list(pattern.finditer(document_text or ""))
    contexts = []
    for match in matches:
        start, end = max(0, match.start() - 500), min(len(document_text), match.end() + 500)
        excerpt = document_text[start:end]
        if alias_occurs(excerpt, aliases, normalized_aliases, uid):
            contexts.append(excerpt)
    # Repeated mentions inside one document are still one source. The caller
    # separately requires that exactly one manifest document matches.
    return contexts[0] if contexts else ""


def observation_has_policy_pii(obs: Observation, case_aliases: set[str], norm_aliases: set[str], uid: str) -> bool:
    # If explicit PII fields are filled, that is sufficient for categories requiring
    # anonymization/redaction even when the exact value is no longer in the alias list.
    if fields_have_direct_pii(obs.fields, obs.raw_text):
        return True
    # Stable references make analytics attributable; callers apply category-specific policy.
    for k, v in obs.fields.items():
        keytail = str(k).lower().split(".")[-1]
        if keytail in {"user_id", "customer_reference", "subject_reference", "subject_selector", "customer_ref", "user_ref"} and field_is_present(v):
            # Only the generic test; callers decide category-specific semantics.
            return True
    return False


def is_non_deletion_request(text: str) -> bool:
    """Conservative explicit-intent classifier: return True only for clear non-delete actions."""
    t = norm_text(text)
    raw = (text or "").casefold()
    # Explicit statements that the message is not a deletion request override generic wording.
    explicit_nondelete = [
        r"not a request to erase", r"not asking for deletion", r"not asking for delete",
        r"not asking you to delete", r"not requesting deletion", r"i am not asking for deletion",
        r"do not close the account", r"don't close the account", r"do not delete", r"don't delete",
        r"please don't delete", r"leave the account active", r"leave my account active",
        r"keep the account as it is", r"please keep the account as it is", r"still want the account",
        r"i still use it", r"i still use the service", r"without removing any of my records",
        r"leave my profile and purchase history in place", r"not asking for deletion",
    ]
    if any(re.search(p, raw, re.I) for p in explicit_nondelete):
        return True
    # Non-destructive account actions explicitly asked for instead of deletion.
    nondelete_patterns = [
        r"change the email address", r"change my email", r"update the email address",
        r"replace (the )?(mobile number|phone number)", r"mobile number .* out of date",
        r"surname is misspelled", r"correct (the )?(surname|name|address|phone|mobile)",
        r"reset(ting)? the login", r"reset my password", r"can't access my profile",
        r"cannot access my profile", r"help resetting the login", r"correct it without removing",
        r"stop the promotional emails", r"stop promotional emails", r"remove me from marketing lists only",
        r"marketing lists only", r"promotional emails.*still need", r"marketing opt.?out",
        r"download my account information", r"download .* information in a portable format",
        r"a copy of the information held on my account", r"what personal information do you hold",
        r"information request", r"access request", r"copy of last year'?s invoices",
        r"need a copy of .* invoices", r"please send me a copy", r"request a copy of",
        r"please send .* invoices", r"leave my profile .* in place",
    ]
    if any(re.search(p, raw, re.I) for p in nondelete_patterns):
        return True
    # If the request contains both a deletion verb and an explicit negative constraint,
    # don't misclassify merely because retained categories are mentioned.
    return False


def get_observation_cutoff(obs: Observation, audit_at: datetime) -> bool:
    # Both when the evidence was captured and when the underlying observation
    # occurred must be at or before the case cutoff. A later export may describe
    # an older event, but it was not participant-visible at audit_at.
    return obs.captured_at <= audit_at and obs.observed_at <= audit_at


def activity_nearest_case(request: dict[str, str], all_requests: list[dict[str, str]], activity: Activity) -> tuple[str, float]:
    """Return nearest case to an activity by request/report time, measured in hours."""
    best_case, best = "", float("inf")
    at = activity.event_time
    for r in all_requests:
        rq = parse_time(r.get("requested_at"))
        rp = parse_time(r.get("reported_at"))
        if not rq or not rp:
            continue
        # Event processing tends to cluster around reported_at, but allow early intake actions.
        dist = min(abs((at - rp).total_seconds()), abs((at - rq).total_seconds()) * 1.20) / 3600.0
        if dist < best:
            best_case, best = r["case_id"], dist
    return best_case, best



def account_delete_result_matches_status(activity: Activity, request: dict[str, str]) -> bool:
    """Return a weak activity/workflow association cue, never state evidence."""
    if activity.event_type != "DELETE_RECORD" or activity.target_system != "account_service":
        return False
    result = (activity.reported_result or "").strip().upper()
    status = (request.get("reported_status") or "").strip().upper()
    if status == "COMPLETE":
        return result in {"SUCCESS", "SUCCEEDED", "COMPLETED"}
    if status == "PARTIALLY_COMPLETE":
        return result in {"PARTIAL", "PARTIALLY_COMPLETE", "SUCCESS"}
    if status == "NOT_STARTED":
        return result in {"FAILED", "ERROR", "NOT_STARTED"}
    return False


def activity_conflicts_user(activity: Activity, alias_set: set[str], uid: str) -> bool:
    """Reject weak activity matches with an explicit, differently identified subject."""
    keyed_values = activity.identity_fields
    if keyed_values is None:
        keyed_values = parse_activity_identity_fields(activity.details)

    subject_keys = {
        "user_id", "user_ref", "user_reference", "subject_id", "subject_ref",
        "subject_reference", "customer_id", "customer_ref", "customer_reference",
    }
    for key in subject_keys:
        for value in keyed_values.get(key, []):
            if re.fullmatch(r"user_[A-Za-z0-9-]+", value, re.I) and value.casefold() != uid.casefold():
                return True

    email_keys = {"email", "user_email", "subject_email", "customer_email", "requester_email"}
    explicit_emails = {value.casefold() for key in email_keys for value in keyed_values.get(key, [])
                       if "@" in value}
    if explicit_emails and not any(email in alias_set for email in explicit_emails):
        return True

    phone_keys = {"phone", "user_phone", "subject_phone", "customer_phone", "requester_phone"}
    explicit_phones = [digits(value) for key in phone_keys for value in keyed_values.get(key, [])
                       if len(digits(value)) >= 8]
    alias_phones = {digits(alias) for alias in alias_set if len(digits(alias)) >= 8}
    if explicit_phones and alias_phones and not any(phone in alias_phones for phone in explicit_phones):
        return True
    return False


def assign_activity_nearest_case(all_requests: list[dict[str, str]], activities: list[Activity],
                                 _scan_requests: bool = False) -> dict[str, tuple[str, float]]:
    """Assign ambiguous activity to requests while avoiding many-to-one analytics collisions.

    Explicit identity/resource links are evaluated later and remain stronger than this
    weak time-based fallback. For anonymization events with overlapping request windows,
    scope cues and a one-analytics-event-per-case slot reduce false cross-case attribution.
    """
    out: dict[str, tuple[str, float]] = {}
    relevant_types = {
        "DELETE_RECORD", "UPDATE_RECORD", "SYNC_RECORD", "INDEX_RECORD", "REFRESH_CACHE",
        "REDACT_RECORD", "ANONYMIZE_RECORD", "RETAIN_RECORD", "CHECK_DATA_FLOW",
        "DISABLE_DATA_FLOW", "CHECK_RESTORE_ACCESS", "BLOCK_RESTORE", "RESTORE_BACKUP",
        "CREATE_EXPORT", "CLASSIFY_REQUEST",
    }
    analytics_slot_used: set[str] = set()

    def result_penalty(a: Activity, r: dict[str, str]) -> int:
        if a.event_type != "DELETE_RECORD" or a.target_system != "account_service":
            return 0
        return 0 if account_delete_result_matches_status(a, r) else 1

    # A report-time range is a lossless candidate index because the existing
    # eligibility rule already requires the event to be within four hours of it.
    parsed_requests = []
    for request in all_requests:
        requested_at = parse_time(request.get("requested_at"))
        reported_at = parse_time(request.get("reported_at"))
        if requested_at and reported_at:
            parsed_requests.append((reported_at, request.get("case_id", ""), requested_at, request))
    parsed_requests.sort(key=lambda item: (item[0], item[1]))
    report_times = [item[0] for item in parsed_requests]

    for a in sorted(activities, key=lambda item: (item.event_time, item.activity_id)):
        if a.event_type not in relevant_types:
            out[a.activity_id] = ("", float("inf"))
            continue
        at = a.event_time
        candidates = []
        if _scan_requests:
            request_candidates = [(parse_time(r.get("reported_at")), r.get("case_id", ""),
                                   parse_time(r.get("requested_at")), r) for r in all_requests]
        else:
            left = bisect_left(report_times, at - timedelta(hours=4))
            right = bisect_right(report_times, at + timedelta(hours=4))
            request_candidates = parsed_requests[left:right]
        for rp, _, rq, r in request_candidates:
            if not rq or not rp or not (rq <= at <= rp + timedelta(minutes=15)):
                continue
            report_delta = abs((rp - at).total_seconds()) / 3600.0
            if report_delta > 4.0:
                continue
            candidates.append((
                result_penalty(a, r),
                report_delta,
                (at - rq).total_seconds() / 3600.0,
                r.get("case_id", ""),
                r,
            ))

        if not candidates:
            out[a.activity_id] = ("", float("inf"))
            continue

        is_analytics_anonymize = (
            a.event_type == "ANONYMIZE_RECORD"
            and (a.target_system == "analytics_platform" or a.resource_id.startswith(("analytics_", "sessions_")))
        )
        if is_analytics_anonymize:
            # Remove explicitly narrow non-analytics scopes when another relevant request
            # is available; do not discard the event if this is the only possible request.
            non_narrow = [c for c in candidates if not _request_has_narrow_non_analytics_scope(c[4].get("request_text", ""))]
            if non_narrow:
                candidates = non_narrow

            # If one or more requests explicitly discuss analytics/anonymization/identifiability,
            # prefer them over a merely time-near generic deletion request.
            strongly_scoped = [c for c in candidates if _analytics_scope_score(c[4].get("request_text", "")) > 0]
            if strongly_scoped:
                candidates = strongly_scoped

            # A case should not inherit several anonymous analytics records just because
            # their anonymization events occur inside a shared request/reporting window.
            available = [c for c in candidates if c[3] not in analytics_slot_used]
            if available:
                candidates = available

        is_account_delete = a.event_type == "DELETE_RECORD" and a.target_system == "account_service"
        if is_account_delete:
            # Time windows identify plausible requests, not ownership. A status/result
            # match can weakly distinguish one request from other plausible requests,
            # but ties and status mismatches remain explicitly ambiguous. Direct
            # subject/resource links are handled later and do not depend on this map.
            consistent = [c for c in candidates if c[0] == 0]
            if len(consistent) != 1:
                out[a.activity_id] = ("", min(c[1] for c in candidates))
                continue
            best = consistent[0]
        else:
            best = min(candidates, key=lambda c: c[:4])
        selected_case = best[3]
        out[a.activity_id] = (selected_case, best[1])
        if is_analytics_anonymize:
            analytics_slot_used.add(selected_case)

    return out

def infer_activity_candidates(request: dict[str, str], all_requests: list[dict[str, str]], activities: list[Activity],
                              linked_resource_ids: set[str], alias_set: set[str], normalized_aliases: set[str], uid: str,
                              nearest_case_by_activity: dict[str, tuple[str, float]],
                              retrieval_index: Optional[ActivityRetrievalIndex] = None,
                              _scan_retrieval: bool = False) -> dict[str, list[Activity]]:
    """Use activity primarily for identity/resource linkage, never as sole proof of state."""
    audit_at = parse_time(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
    out: dict[str, list[Activity]] = defaultdict(list)
    request_time = parse_time(request.get("requested_at"))
    activity_pool = activities
    if retrieval_index is not None and not _scan_retrieval:
        activity_pool = retrieval_index.candidates_for(
            request.get("case_id", ""), linked_resource_ids, alias_set, normalized_aliases
        )

    def is_weak_time_match(activity: Activity) -> bool:
        nearest_id, dist = nearest_case_by_activity.get(activity.activity_id, ("", float("inf")))
        return (
            nearest_id == request.get("case_id")
            and dist <= 4.0
            and (request_time is None or activity.event_time >= request_time)
            and activity.event_type in {
                "DELETE_RECORD", "UPDATE_RECORD", "SYNC_RECORD", "INDEX_RECORD", "REFRESH_CACHE",
                "REDACT_RECORD", "ANONYMIZE_RECORD", "RETAIN_RECORD", "CHECK_DATA_FLOW",
                "DISABLE_DATA_FLOW", "CHECK_RESTORE_ACCESS", "BLOCK_RESTORE", "RESTORE_BACKUP",
                "CREATE_EXPORT", "CLASSIFY_REQUEST",
            }
        )

    # Explicit identity/resource links take priority. Otherwise, a result that
    # agrees with the workflow status is only a weak tie-breaker among nearby
    # account deletion events; neither value is evidence of actual resource state.
    explicit_account_resources: set[str] = set()
    for activity in activity_pool:
        if activity.event_time > audit_at or activity.event_type != "DELETE_RECORD" or activity.target_system != "account_service":
            continue
        strong = alias_occurs(activity.details, alias_set, normalized_aliases, uid) or alias_occurs(activity.resource_id, alias_set, normalized_aliases, uid)
        conflict = activity_conflicts_user(activity, alias_set, uid)
        if activity.resource_id in linked_resource_ids or (strong and not conflict):
            explicit_account_resources.add(activity.resource_id)
    # Create an activity-to-case assignment for narrowly-timed resource discovery.
    for a in activity_pool:
        if a.event_time > audit_at:
            continue
        # Exact identity reference in activity details is a strong association.
        strong = alias_occurs(a.details, alias_set, normalized_aliases, uid) or alias_occurs(a.resource_id, alias_set, normalized_aliases, uid)
        relevant = False
        if a.resource_id in linked_resource_ids:
            relevant = True
        elif activity_conflicts_user(a, alias_set, uid):
            continue
        elif strong:
            relevant = True
        elif is_weak_time_match(a):
            if a.event_type == "DELETE_RECORD" and a.target_system == "account_service":
                if explicit_account_resources and a.resource_id not in explicit_account_resources:
                    continue
                # Ambiguity is resolved per activity in assign_activity_nearest_case.
                # Do not collapse several separately attributable resources for this
                # request merely because they share the same weak association tier.
                if not explicit_account_resources and not account_delete_result_matches_status(a, request):
                    continue
            # Time proximity is only a fallback for events after the request was made.
            relevant = True
        if relevant:
            out[a.resource_id].append(a)
    return out


def state_value(obs: Observation) -> str:
    if obs.explicit_state:
        return obs.explicit_state
    return "PRESENT"


def pii_present(obs: Observation, uid: str = "") -> bool:
    # Category-specific link fields are added below where relevant.
    if fields_have_direct_pii(obs.fields, obs.raw_text):
        return True
    f = {str(k).lower().split(".")[-1]: v for k, v in obs.fields.items()}
    # Retained/direct link fields make analytics attributable, unlike permitted stable links in other categories.
    for key in ("user_id", "customer_reference", "subject_reference", "subject_selector", "customer_ref", "user_ref"):
        if key in f and field_is_present(f[key]):
            return True
    raw = (obs.raw_text or "").upper()
    if "IDENTIFIABLE" in raw:
        return True
    return False


def select_latest_observation(observations: list[Observation], audit_at: datetime) -> Optional[Observation]:
    eligible = [o for o in observations if get_observation_cutoff(o, audit_at)]
    if not eligible:
        return None
    def priority(o: Observation) -> int:
        # In log traces, a start and completion line often share the same second.
        # Prefer the completed/result line, not the earlier *_started record.
        raw = (o.raw_text or "").casefold()
        p = 0
        if any(t in raw for t in ("_completed", "_complete", "http_status=", "status_code=", "rows=", "result=", "restore_allowed=", "enabled=")):
            p += 3
        if "_started" in raw or "_starting" in raw:
            p -= 2
        if o.explicit_state in {"ABSENT", "ANONYMIZED", "REDACTED", "DISABLED", "BLOCKED"}:
            p += 2
        if o.record_kind not in {"line", "document"}:
            p += 1
        return p
    return max(eligible, key=lambda o: (o.observed_at, priority(o), o.captured_at))


def export_expired_by(obs: Observation, audit_at: datetime) -> bool:
    """A screenshot of an export package is stale after its displayed expiry."""
    if not re.search(r"\bexpires?\b", obs.raw_text or "", re.I):
        return False
    match = re.search(r"\bExpires?\s*:?[ \n]+(\d{1,2} [A-Za-z]{3} 20\d{2} \d{2}:\d{2} UTC)", obs.raw_text or "", re.I)
    if not match:
        return False
    try:
        expires = datetime.strptime(match.group(1), "%d %b %Y %H:%M UTC").replace(tzinfo=timezone.utc)
        return expires < audit_at
    except ValueError:
        return False


def snapshot_absence_evidence(index: EvidenceIndex, resource_id: str, audit_at: datetime) -> Optional[str]:
    system = infer_system(resource_id)
    eligible = [(sysid, file_id, when, table) for sysid, file_id, when, table in index.snapshot_coverage if when <= audit_at]
    # Latest SQL snapshot that covers the resource's service and does not contain it can support absence.
    for sysid, file_id, when, table in sorted(eligible, key=lambda x: x[2], reverse=True):
        if sysid == system and resource_id not in index.by_resource:
            return file_id
        if sysid == system:
            obs = [o for o in index.by_resource.get(resource_id, []) if o.file_id == file_id and get_observation_cutoff(o, audit_at)]
            if not obs:
                return file_id
    return None


def policy_decision(candidate: Candidate, obs: Observation, uid: str, audit_at: datetime) -> tuple[str, str, str, str]:
    """Return (finding operation or '', required remediation op or '', target verification op, target state)."""
    cat = candidate.category
    state = state_value(obs)
    fields = {str(k).lower().split(".")[-1]: v for k, v in obs.fields.items()}
    raw = obs.raw_text or ""
    present = state != "ABSENT"
    direct_pii = fields_have_direct_pii(obs.fields, raw)
    # Analytics must be unlinkable, so stable reference fields count as attribution.
    attributable = direct_pii or any(field_is_present(fields.get(k)) for k in ("user_id", "customer_reference", "subject_reference", "subject_selector", "user_ref", "customer_ref"))

    if state == "ABSENT":
        return "", "", "VERIFY_RECORD_ABSENT", "ABSENT"
    if cat in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE"}:
        return "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"
    if cat == "SUPPORT_ATTACHMENT":
        # Attachment-only artifacts are removed rather than retaining a whole document.
        if direct_pii or state == "PRESENT":
            return "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"
        return "", "", "VERIFY_RECORD_ABSENT", "ABSENT"
    if cat == "SUPPORT_MESSAGE":
        if direct_pii or ("IDENTIFIABLE" in raw.upper()):
            return "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REDACTED"
        return "", "", "VERIFY_RECORD_REDACTED", "REDACTED"
    if cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if attributable or state == "PRESENT" and "ANONYMIZED" not in raw.upper() and direct_pii:
            return "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        return "", "", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
    if cat == "EMAIL_DELIVERY_LOG":
        # Delivery logs may be retained operationally but must not expose the user's email.
        if direct_pii:
            return "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REDACTED"
        return "", "", "VERIFY_RECORD_REDACTED", "REDACTED"
    if cat == "SECURITY_AUDIT_LOG":
        until = parse_time(fields.get("retention_until"))
        if until is None or until >= audit_at:
            return "", "", "VERIFY_RECORD_PRESENT", "PRESENT"
        return "", "", "VERIFY_RECORD_PRESENT", "PRESENT"
    if cat == "LEGAL_HOLD_RECORD":
        active = str(fields.get("active", fields.get("hold_active", "true"))).lower() not in {"false", "0", "no", "expired"}
        if active:
            return "", "", "VERIFY_RECORD_PRESENT", "PRESENT"
        return "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT", "ABSENT"
    if cat == "BACKUP_ARCHIVE":
        restore_allowed = str(fields.get("restore_allowed", "")).lower() in {"true", "1", "yes"}
        status_active = state == "ACTIVE" or str(fields.get("status", "")).upper() == "ACTIVE"
        retention_until = parse_time(fields.get("retention_until"))
        if restore_allowed or status_active:
            return "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        if state not in {"BLOCKED", "ABSENT"} and retention_until and retention_until > audit_at:
            # A retained archive within its stated retention window can restore
            # subject data even when the console omits a restore_allowed flag.
            return "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        return "", "", "VERIFY_RESTORE_BLOCKED", "BLOCKED"
    if cat == "DATA_FLOW":
        enabled = str(fields.get("enabled", "")).lower() in {"true", "1", "yes"}
        status_active = state == "ACTIVE" or str(fields.get("status", "")).upper() == "ACTIVE"
        live_continuous_traffic = (
            re.search(r"\bCONTINUOUS\b", raw, re.I) is not None
            and re.search(r"events\s*/\s*hour[\s\S]{0,120}?\n\s*[1-9][\d,]*\b", raw, re.I) is not None
        )
        if enabled or status_active or live_continuous_traffic:
            return "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        return "", "", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
    if cat == "ACCOUNT_TOMBSTONE":
        if direct_pii:
            return "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED", "REDACTED"
        return "", "", "VERIFY_RECORD_REDACTED", "REDACTED"
    return "", "", "", ""



def _analytics_scope_score(request_text: str) -> int:
    """Strong cue that the request focuses on analytics privacy/anonymization, not merely mentions analytics."""
    txt = norm_text(request_text)
    strong = (
        r"\bstatistics?\b", r"\banonym(?:ous|ized|ise|isation|ization)?\b",
        r"\bidentifiable analytics\b", r"\banalytics data\b",
        r"\bcannot identify\b", r"\bcan.?t identify\b", r"\bidentify me\b",
        r"\bpoint back\b", r"\bemail hash\b", r"\bhash\b",
    )
    return 2 if any(re.search(p, txt, re.I) for p in strong) else 0


def _request_has_narrow_non_analytics_scope(request_text: str) -> bool:
    """True only for requests that explicitly focus on another artifact class."""
    txt = norm_text(request_text)
    narrow = (
        r"\bsupport conversations?\b", r"\bsupport messages?\b", r"\bidentity document\b",
        r"\bdownloadable archive\b", r"\bexport file\b", r"\bdata export\b",
        r"\baccount and (?:its )?search result\b",
    )
    return _analytics_scope_score(request_text) == 0 and any(re.search(p, txt, re.I) for p in narrow)


def find_case_candidates(request: dict[str, str], all_requests: list[dict[str, str]], index: EvidenceIndex,
                         activities: list[Activity], maps,
                         nearest_case_by_activity: dict[str, tuple[str, float]],
                         activity_index: Optional[ActivityRetrievalIndex] = None,
                         _scan_retrieval: bool = False) -> tuple[str, dict[str, Candidate], set[str], set[str]]:
    audit_at = parse_time(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
    uid, aliases, norm_aliases = resolve_identity(request, maps, audit_at)
    direct_obs: list[Observation] = []
    association_reasons: dict[str, list[str]] = defaultdict(list)
    related_document_ids: dict[str, set[str]] = defaultdict(set)
    document_link_only_ids: set[str] = set()
    rejected_conflicts: list[dict[str, str]] = []
    ambiguous_candidates: list[dict[str, str]] = []
    observation_pool = index.observations if _scan_retrieval else index.identity_candidates(aliases, norm_aliases)
    for obs in observation_pool:
        if not get_observation_cutoff(obs, audit_at):
            continue
        if observation_conflicts_user(obs, aliases, norm_aliases, uid):
            continue
        if obs_matches_user(obs, aliases, norm_aliases, uid):
            obs.linked = True
            direct_obs.append(obs)
            association_reasons[obs.resource_id].append(f"exact identity match in {obs.file_id}")
    linked_ids: set[str] = set()
    for obs in direct_obs:
        linked_ids.add(obs.resource_id)
        for related_id in related_resource_ids(obs):
            linked_ids.add(related_id)
            association_reasons[related_id].append(f"explicit resource link from {obs.file_id}/{obs.resource_id}")
    # Expand only the resource-linked observations. The complete direct identity
    # match set was already collected above, so rescanning every observation here
    # cannot discover a new direct match; it only computes transitive resource links.
    processed_resources: set[str] = set()
    while linked_ids - processed_resources:
        current_resources = linked_ids - processed_resources
        processed_resources.update(current_resources)
        related_observations = {
            id(obs): obs for resource_id in current_resources
            for obs in index.by_resource.get(resource_id, ())
        }
        for obs in sorted(related_observations.values(),
                          key=lambda item: index._identity_search.order.get(id(item), 0)):
            if not get_observation_cutoff(obs, audit_at):
                continue
            for related_id in related_resource_ids(obs) - linked_ids:
                linked_ids.add(related_id)
                association_reasons[related_id].append(
                    f"explicit resource link from {obs.file_id}/{obs.resource_id}"
                )

    # Activity is used for resource discovery, not as proof of actual state.
    activity_candidates = infer_activity_candidates(
        request, all_requests, activities, linked_ids, aliases, norm_aliases, uid,
        nearest_case_by_activity, activity_index, _scan_retrieval
    )

    # A data-catalog link can identify a document by a business reference instead
    # of a filename or resource_id. Record that explicit association for diagnostics
    # and candidate discovery, but do not turn the document into a state observation.
    # A separate cutoff-valid resource readback is still required before any finding.
    for rid, entries in activity_candidates.items():
        for activity in entries:
            if activity.event_type != "LINK_RESOURCE_IDENTITY" or not alias_occurs(activity.details, aliases, norm_aliases, uid):
                continue
            for reference in explicit_reference_tokens(activity):
                matches = []
                for doc in index.document_texts:
                    if doc[2] > audit_at:
                        continue
                    excerpt = find_exact_reference_context(doc[3], reference, aliases, norm_aliases, uid)
                    if excerpt:
                        doc_fields = EvidenceIndex._parse_kv_fields(excerpt)
                        document_uids = set(re.findall(r"\buser_[A-Za-z0-9-]+\b", excerpt, re.I))
                        if document_uids and not any(value.casefold() == uid.casefold() for value in document_uids):
                            continue
                        doc_emails = {value.casefold() for value in EMAIL_RE.findall(excerpt)}
                        if doc_emails and not any(value in aliases for value in doc_emails):
                            continue
                        evidence_stub = Observation(doc[0], doc[1], doc[2], doc[2], rid,
                                                    activity.target_system, doc_fields, excerpt, "document")
                        if observation_conflicts_user(evidence_stub, aliases, norm_aliases, uid):
                            continue
                        matches.append((doc, excerpt))
                if len(matches) != 1:
                    if matches:
                        rejected_conflicts.append({
                            "activity_id": activity.activity_id,
                            "resource_id": rid,
                            "reason": f"reference {reference} occurs in multiple cutoff-eligible documents",
                        })
                    continue
                (file_id, rel, captured, _), excerpt = matches[0]
                document_link_only_ids.add(rid)
                association_reasons[rid].append(
                    f"explicit catalog reference {reference} corroborated by {file_id} via {activity.activity_id}; state unproven"
                )
                related_document_ids[rid].add(file_id)

    # A strong catalog link may name an artifact by filename while a screenshot
    # shows the filename but has no OCR-readable resource ID. Bridge those only
    # when the activity explicitly links this subject and exactly one pre-cutoff
    # participant-facing document contains the same filename.
    for rid, entries in activity_candidates.items():
        for activity in entries:
            if (activity.event_type != "LINK_RESOURCE_IDENTITY"
                    or not alias_occurs(activity.details, aliases, norm_aliases, uid)):
                continue
            names = re.findall(r"[A-Za-z0-9_.-]+\.(?:pdf|zip|csv|json)", activity.details, re.I)
            if not names:
                continue
            filename = names[0]
            needle = norm_text(filename).replace(" ", "")
            matches = [doc for doc in index.document_texts
                       if doc[2] <= audit_at and audit_at - doc[2] <= timedelta(days=14)
                       and needle in norm_text(doc[3]).replace(" ", "")]
            if len(matches) != 1:
                continue
            file_id, rel, captured, _ = matches[0]
            obs = Observation(file_id, rel, captured, captured, rid, activity.target_system,
                              {"filename": filename}, "filename=" + filename, "document", "PRESENT")
            if not any(o.file_id == file_id and o.resource_id == rid for o in index.by_resource.get(rid, [])):
                index.by_resource[rid].append(obs)
            linked_ids.add(rid)
            association_reasons[rid].append(f"unique filename reference {filename} in {file_id} via {activity.activity_id}")
            related_document_ids[rid].add(file_id)

    # Preserve explicit subject-to-resource links carried by analytics activity. These
    # are stronger than the temporal fallback and remain eligible even when the readback
    # itself has been anonymized and no longer contains identifiers.
    for rid, entries in activity_candidates.items():
        if not rid.startswith(("analytics_", "sessions_")) or rid in linked_ids:
            continue
        if any(alias_occurs(activity.details, aliases, norm_aliases, uid) for activity in entries):
            linked_ids.add(rid)
            association_reasons[rid].append("explicit subject reference in analytics activity")

    # A temporal anonymization event plus an anonymous readback establishes the
    # resource's state, but not which subject it belongs to. Do not select one weak
    # analytics candidate by earliest event time (or request wording) when identity
    # attribution is absent. Keep the rejection visible in diagnostics instead.
    weak_analytics = [
        rid for rid, entries in activity_candidates.items()
        if rid.startswith(("analytics_", "sessions_")) and rid not in linked_ids
        and entries and not any(
            get_observation_cutoff(o, audit_at) and obs_matches_user(o, aliases, norm_aliases, uid)
            for o in index.by_resource.get(rid, [])
        )
    ]
    for rid in weak_analytics:
        ambiguous_candidates.append({
            "resource_id": rid,
            "reason": "analytics activity/readback lacks a subject link; temporal proximity cannot establish ownership",
        })
        activity_candidates.pop(rid, None)

    # If a case has both post-report and pre-report account deletion events in a temporal
    # collision, ignore the later events. Keep a sole event even when it is logged just after
    # reported_at because some workflows persist their completion telemetry asynchronously.
    reported_at = parse_time(request.get("reported_at"))
    weak_account = {
        rid: entries for rid, entries in activity_candidates.items()
        if infer_system(rid) == "account_service" and rid not in linked_ids
    }
    if reported_at and any(a.event_time <= reported_at for ents in weak_account.values() for a in ents):
        for rid, entries in list(weak_account.items()):
            filtered = [a for a in entries if a.event_time <= reported_at]
            if filtered:
                activity_candidates[rid] = filtered
            else:
                activity_candidates.pop(rid, None)

    has_linked_account_resource = any(infer_system(rid) == "account_service" for rid in linked_ids)
    # If the target user's account resource is already identified by evidence, do not
    # attach unrelated time-neighbour account deletion submissions to the same case.
    activity_account_ids_with_observed_absence = set()
    for arid, aentries in activity_candidates.items():
        if infer_system(arid) != "account_service" or arid in linked_ids:
            continue
        aobs = [o for o in index.by_resource.get(arid, []) if get_observation_cutoff(o, audit_at)]
        if not aobs:
            continue
        if any(observation_conflicts_user(o, aliases, norm_aliases, uid) for o in aobs):
            continue
        acurrent = select_latest_observation(aobs, audit_at)
        if acurrent and state_value(acurrent) == "ABSENT":
            activity_account_ids_with_observed_absence.add(arid)
    for rid, entries in activity_candidates.items():
        if rid in linked_ids:
            continue
        is_account_candidate = infer_system(rid) == "account_service"
        if is_account_candidate and has_linked_account_resource:
            continue
        if is_account_candidate and rid not in index.by_resource and activity_account_ids_with_observed_absence:
            # Prefer the evidence-backed absent account observation over a second
            # activity-only account ID from the same ambiguous time cluster.
            continue
        # Only add temporal candidates when a corresponding evidence observation exists; absent account
        # resources can still be discovered from account-service delete events.
        eligible_obs = [o for o in index.by_resource.get(rid, []) if get_observation_cutoff(o, audit_at)]
        if eligible_obs:
            current = select_latest_observation(eligible_obs, audit_at)
            if any(observation_conflicts_user(o, aliases, norm_aliases, uid) for o in eligible_obs):
                # Timeline proximity cannot override an as-of-cutoff observation
                # proving that this stable resource ID belongs to another customer.
                rejected_conflicts.append({
                    "resource_id": rid,
                    "reason": "time-neighbor activity rejected because the resource observation conflicts with the subject",
                })
                continue
            # Only use time-only linkage for primary account records with an explicit absent
            # readback; other systems must be identity-linked or reached through resource links.
            if infer_system(rid) == "account_service" and current and state_value(current) == "ABSENT":
                linked_ids.add(rid)
        elif infer_system(rid) == "account_service" and any(a.event_type == "DELETE_RECORD" for a in entries):
            # A deletion event plus a covering snapshot can support an absence verification.
            linked_ids.add(rid)

    # Keep document-only links out of policy and weak-association decisions above.
    # They are candidate discoveries for diagnostics until a state observation exists.
    linked_ids.update(document_link_only_ids)
    candidates: dict[str, Candidate] = {}
    for rid in sorted(linked_ids):
        # Resource identifiers are not guaranteed globally unique across exports or
        # synthetic/test snapshots. A strong match for this subject must not cause a
        # contradictory observation for another explicit identity to enter the
        # candidate's state timeline.
        eligible = [o for o in index.by_resource.get(rid, [])
                    if get_observation_cutoff(o, audit_at)
                    and not observation_conflicts_user(o, aliases, norm_aliases, uid)]
        # Direct evidence may include older identity-bearing states. Preserve all eligible observations
        # so the latest observation can determine whether a record was later redacted/anonymized.
        system = infer_system(rid)
        if eligible:
            system = eligible[-1].system_id or system
            current = select_latest_observation(eligible, audit_at) or eligible[-1]
            cat = candidate_category(rid, current.system_id, current.fields, current.raw_text, current.file_path)
        else:
            entries = activity_candidates.get(rid, [])
            system = entries[-1].target_system if entries else system
            cat = candidate_category(rid, system, {}, "", "")
        activity_entries = activity_candidates.get(rid, [])
        reasons = association_reasons.get(rid, []).copy()
        for activity in activity_entries:
            if activity.event_type == "LINK_RESOURCE_IDENTITY" and alias_occurs(activity.details, aliases, norm_aliases, uid):
                reasons.append(f"explicit subject-resource link in {activity.activity_id}")
            elif alias_occurs(activity.details, aliases, norm_aliases, uid):
                reasons.append(f"exact identity in activity details {activity.activity_id}; activity is not state proof")
            elif nearest_case_by_activity.get(activity.activity_id, ("", 0))[0] == request.get("case_id"):
                reasons.append(f"weak time-window association in {activity.activity_id}; requires evidence readback")
        candidates[rid] = Candidate(rid, system, cat, eligible, activity_entries,
                                    any(o in direct_obs for o in eligible), reasons,
                                    sorted(related_document_ids.get(rid, set())))

    index.diagnostics_by_case[request.get("case_id", "")] = {
        "case_id": request.get("case_id", ""),
        "audit_at": request.get("audit_at", ""),
        "resolved_user_id": uid,
        "aliases": sorted(aliases),
        "candidates": [
            {
                "resource_id": candidate.resource_id,
                "system_id": candidate.system_id,
                "category": candidate.category,
                "association_reasons": candidate.association_reasons,
                "related_document_ids": candidate.related_document_ids,
                "activities": [
                    {
                        "activity_id": activity.activity_id,
                        "event_time": activity.event_time.isoformat(),
                        "event_type": activity.event_type,
                        "source_system": activity.source_system,
                        "target_system": activity.target_system,
                        "resource_id": activity.resource_id,
                        "reported_result_claim": activity.reported_result,
                    }
                    for activity in candidate.related_by_activity
                ],
                "observations": [
                    {
                        "evidence_id": obs.file_id,
                        "captured_at": obs.captured_at.isoformat(),
                        "observed_at": obs.observed_at.isoformat(),
                        "observation_time_source": "manifest capture fallback" if obs.observed_at == obs.captured_at else "source-derived timestamp",
                        "state": state_value(obs),
                        "state_eligible": not (candidate.category == "USER_EXPORT" and export_expired_by(obs, audit_at)),
                        "state_exclusion_reason": "expired before audit_at" if candidate.category == "USER_EXPORT" and export_expired_by(obs, audit_at) else "",
                        "validity_fields": {
                            key: value for key, value in obs.fields.items()
                            if any(token in str(key).lower().split(".")[-1] for token in ("expires", "expiry", "retention", "valid_from", "valid_to", "valid_until"))
                        },
                        "timestamp_mentions": [(raw, parsed.isoformat()) for raw, parsed in obs.timestamp_mentions],
                        "timestamp_warnings": obs.timestamp_warnings,
                    }
                    for obs in candidate.observations
                ],
            }
            for candidate in candidates.values()
        ],
        "rejected_conflicts": rejected_conflicts,
        "ambiguous_candidates": ambiguous_candidates,
        "empty_plan_reason": "no current policy-relevant state observation" if not any(
            obs for candidate in candidates.values() for obs in candidate.observations
            if not (candidate.category == "USER_EXPORT" and export_expired_by(obs, audit_at))
        ) else "",
    }

    return uid, candidates, aliases, norm_aliases


def make_step(phase: str, system_id: str, resource_id: str, operation: str, state: str, evidence_id: str) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id or infer_system(resource_id),
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id or "",
    }


def sort_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps.sort(key=lambda s: (
        PHASE_RANK.get(s["phase"], 99),
        OPERATION_RANK.get(s["phase"], {}).get(s["operation"], 99),
        s["system_id"],
        s["resource_id"],
    ))
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return steps


def best_evidence_id(candidate: Candidate, obs: Optional[Observation], index: EvidenceIndex, audit_at: datetime) -> str:
    if obs:
        return obs.file_id
    # If a full SQLite snapshot covers a service, and the candidate is absent from that snapshot,
    # the snapshot ID can support the absence verification.
    return snapshot_absence_evidence(index, candidate.resource_id, audit_at) or ""


def build_case_output(request: dict[str, str], all_requests: list[dict[str, str]], index: EvidenceIndex,
                      activities: list[Activity], maps,
                      nearest_case_by_activity: dict[str, tuple[str, float]],
                      activity_index: Optional[ActivityRetrievalIndex] = None,
                      _scan_retrieval: bool = False) -> dict[str, str]:
    audit_at = parse_time(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
    if is_non_deletion_request(request.get("request_text", "")):
        return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

    uid, candidates, aliases, norm_aliases = find_case_candidates(
        request, all_requests, index, activities, maps, nearest_case_by_activity,
        activity_index, _scan_retrieval
    )
    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    any_violation = False

    # Make current resource state decisions for every candidate. A candidate with no evidence at the cutoff
    # is omitted rather than using later facts or the activity result as proof.
    evaluated: dict[str, tuple[Candidate, Optional[Observation], str, str, str, str]] = {}
    for rid, cand in candidates.items():
            # Only evidence captured by audit_at is eligible to establish state.
        state_obs = [o for o in cand.observations
                     if o.captured_at <= audit_at
                     and not (cand.category == "USER_EXPORT" and export_expired_by(o, audit_at))]
        obs = select_latest_observation(state_obs, audit_at)
        if not obs:
            # We can still use an explicit SQL snapshot absence for account resources.
            abs_eid = snapshot_absence_evidence(index, rid, audit_at)
            if abs_eid and cand.category == "USER_PROFILE":
                evaluated[rid] = (cand, None, "", "", "VERIFY_RECORD_ABSENT", "ABSENT")
            continue
        cand.category = candidate_category(rid, obs.system_id, obs.fields, obs.raw_text, obs.file_path)
        fop, rop, vop, vstate = policy_decision(cand, obs, uid, audit_at)
        ev_state = state_value(obs)
        evaluated[rid] = (cand, obs, fop, rop, vop, vstate)
        if fop:
            any_violation = True
            findings.append(make_step("FINDING", cand.system_id, rid, fop,
                                      "ACTIVE" if fop in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"} else "PRESENT",
                                      obs.file_id))
            remediations.append(make_step("REMEDIATION", cand.system_id, rid, rop, vstate, ""))

    # Add verification for every policy-relevant resource. In incomplete cases, verification is a future
    # step and therefore has a blank evidence_id; in complete cases, only current evidence-backed steps are emitted.
    for rid, (cand, obs, fop, rop, vop, vstate) in evaluated.items():
        if not vop:
            continue
        if any_violation:
            eid = ""
        else:
            eid = best_evidence_id(cand, obs, index, audit_at)
            if not eid and obs:
                eid = obs.file_id
        # A retained security audit record is only verified if it is present and still in the supplied retention period.
        if cand.category == "SECURITY_AUDIT_LOG" and obs:
            fields = {str(k).lower().split(".")[-1]: v for k, v in obs.fields.items()}
            until = parse_time(fields.get("retention_until"))
            if until and until < audit_at:
                continue
            if state_value(obs) == "ABSENT":
                continue
        # Complete answers may cite only evidence that establishes the current compliant state.
        if not any_violation and not eid:
            continue
        verifications.append(make_step("VERIFICATION", cand.system_id, rid, vop, vstate, eid))

    # Ensure all active flow/restore risks are explicitly verified after the proposed action.
    # policy_decision already ensures each applicable candidate is in evaluated.

    status = "INCOMPLETE" if any_violation else "COMPLETE"
    if not evaluated:
        # No current, cutoff-eligible state evidence is not proof of deletion or
        # completion, even if stale/expired candidate records were discovered.
        status = "INCOMPLETE"

    steps = findings + remediations + verifications
    steps = sort_steps(steps)
    payload = json.dumps(steps, ensure_ascii=False, separators=(",", ":"))
    return {"case_id": request["case_id"], "deletion_status": status, "steps_json": payload}


def validate_output(path: Path, expected_case_ids: set[str]) -> list[str]:
    issues: list[str] = []
    try:
        rows = read_csv(path)
    except Exception as e:
        return [f"Could not read output CSV: {e}"]
    expected_header = ["case_id", "deletion_status", "steps_json"]
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        header = next(csv.reader(fh), [])
    if header != expected_header:
        issues.append(f"Header mismatch: {header!r}")
    if len(rows) != len(expected_case_ids):
        issues.append(f"Row count mismatch: got {len(rows)}, expected {len(expected_case_ids)}")
    ids = [r.get("case_id", "") for r in rows]
    if set(ids) != expected_case_ids:
        issues.append(f"Case ID mismatch: missing={len(expected_case_ids-set(ids))}, extra={len(set(ids)-expected_case_ids)}")
    numeric_sort = sorted(ids, key=lambda s: int(s.rsplit("_", 1)[-1]) if s.rsplit("_",1)[-1].isdigit() else s)
    if ids != numeric_sort:
        issues.append("Rows are not sorted by numeric case_id suffix")
    for idx, row in enumerate(rows, 1):
        status = row.get("deletion_status", "")
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            issues.append(f"Row {idx}: invalid status {status!r}")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except Exception as e:
            issues.append(f"Row {idx}: steps_json is not valid JSON ({e})")
            continue
        if not isinstance(steps, list):
            issues.append(f"Row {idx}: steps_json is not an array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            issues.append(f"Row {idx}: NOT_APPLICABLE row must have []")
        for n, s in enumerate(steps, 1):
            if not isinstance(s, dict):
                issues.append(f"Row {idx}: step {n} is not an object")
                continue
            if s.get("step_no") != n:
                issues.append(f"Row {idx}: step numbering is not consecutive")
            required = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
            if set(s) != required:
                issues.append(f"Row {idx}: step {n} keys mismatch: {set(s)^required}")
            if s.get("phase") not in PHASE_RANK:
                issues.append(f"Row {idx}: invalid phase in step {n}")
            if status == "COMPLETE" and s.get("phase") != "VERIFICATION":
                issues.append(f"Row {idx}: COMPLETE row contains non-verification step")
            if status == "INCOMPLETE" and s.get("phase") == "REMEDIATION" and s.get("evidence_id") != "":
                issues.append(f"Row {idx}: future remediation must have blank evidence_id")
            if status == "INCOMPLETE" and s.get("phase") == "VERIFICATION" and s.get("evidence_id") != "":
                issues.append(f"Row {idx}: future verification must have blank evidence_id")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit deletion requests using supplied evidence.")
    parser.add_argument("--dataset", type=Path, default=None, help="Dataset directory (default: repo/dataset)")
    parser.add_argument("--requests", type=Path, default=None, help="Override request CSV, e.g. dataset/sample_deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=None, help="Output CSV (default: repo/output.csv)")
    parser.add_argument("--diagnostics", type=Path, default=None,
                        help="Optional JSON file with candidate links, evidence provenance, and rejection reasons")
    parser.add_argument("--validate-only", action="store_true", help="Validate an existing output.csv")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    # Support both the checked-out layout (code/main.py) and a flattened code.zip
    # layout (main.py alongside evaluation/). Prefer the directory that contains
    # dataset/ when present, otherwise use the conventional repository parent.
    if (script_dir / "dataset").is_dir():
        repo_root = script_dir
    elif (script_dir.parent / "dataset").is_dir():
        repo_root = script_dir.parent
    else:
        repo_root = script_dir.parent if script_dir.name == "code" else script_dir
    dataset_dir = (args.dataset or (repo_root / "dataset")).resolve()
    requests_path = (args.requests or (dataset_dir / "deletion_requests.csv")).resolve()
    output_path = (args.output or (repo_root / "output.csv")).resolve()

    requests = read_csv(requests_path)
    expected_ids = {r["case_id"] for r in requests}
    if args.validate_only:
        if args.diagnostics:
            parser.error("--diagnostics cannot be combined with --validate-only")
        issues = validate_output(output_path, expected_ids)
        if issues:
            print("Validation failed:")
            for issue in issues[:100]: print(" -", issue)
            return 1
        print(f"Validated {len(expected_ids)} output rows: schema, JSON, statuses, phase/evidence constraints look good.")
        return 0

    maps = build_identity_maps(dataset_dir)
    activities = load_activity(dataset_dir)
    print(f"Loaded {len(requests)} requests, {len(activities)} activity events.", file=sys.stderr)
    print("Indexing evidence files (PDF/SQL/JSON/log/text/image OCR where available)...", file=sys.stderr)
    index = EvidenceIndex(dataset_dir)
    print(f"Indexed {len(index.observations)} resource observations from {len(index.manifest)} evidence files.", file=sys.stderr)

    print("Precomputing activity-to-case time windows...", file=sys.stderr)
    nearest_case_by_activity = assign_activity_nearest_case(requests, activities)
    outputs = [build_case_output(r, requests, index, activities, maps, nearest_case_by_activity) for r in requests]
    outputs.sort(key=lambda r: int(r["case_id"].rsplit("_", 1)[-1]) if r["case_id"].rsplit("_",1)[-1].isdigit() else r["case_id"])
    if args.diagnostics:
        diagnostic_cases = dict(index.diagnostics_by_case)
        for request in requests:
            diagnostic_cases.setdefault(request["case_id"], {
                "case_id": request["case_id"],
                "audit_at": request.get("audit_at", ""),
                "resolved_user_id": "",
                "aliases": [],
                "candidates": [],
                "rejected_conflicts": [],
                "ambiguous_candidates": [],
                "empty_plan_reason": "not applicable request",
            })
        args.diagnostics.parent.mkdir(parents=True, exist_ok=True)
        args.diagnostics.write_text(
            json.dumps({"cases": diagnostic_cases}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(outputs)

    counts = defaultdict(int)
    for out in outputs: counts[out["deletion_status"]] += 1
    issues = validate_output(output_path, expected_ids)
    print(f"Wrote {len(outputs)} rows to {output_path}")
    print("Status counts:", dict(counts))
    if issues:
        print("Validation issues:")
        for issue in issues[:100]: print(" -", issue)
        return 1
    print("Output schema validation passed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
