"""Streamlit interface for the local Ghost Data Audit API."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from urllib.parse import urlsplit

import streamlit as st


def classify_api_address(base: str, *, connection_mode: str = "local") -> str:
    """Classify the dashboard's server-side API target without DNS lookups.

    Only the fixed Compose service origin is treated as internal, and only when
    Compose explicitly marks the dashboard connection mode. All other non-loopback
    targets remain external and trigger the dashboard warning.
    """
    try:
        parsed = urlsplit(base)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "external"
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc or not host or
            parsed.username is not None or parsed.password is not None or
            parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        return "external"

    normalized_host = host.casefold().rstrip(".")
    if normalized_host == "localhost":
        return "loopback"
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        address = None
    if address is not None and address.is_loopback:
        return "loopback"

    if (connection_mode.casefold() == "compose_internal" and parsed.scheme == "http" and
            normalized_host == "api" and port == 8000):
        return "compose_internal"
    return "external"


def _api_call(base: str, path: str, method: str = "GET", *, files: dict[str, tuple[str, bytes, str]] | None = None,
              token: str | None = None, timeout: int = 360) -> tuple[object, bytes, str]:
    parsed = urlsplit(base)
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or
            parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise RuntimeError("Enter a valid API origin without credentials or URL parameters.")
    url = base.rstrip("/") + path
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if files is not None:
        boundary = "----GhostAudit" + uuid.uuid4().hex
        chunks: list[bytes] = []
        for field, (filename, content, content_type) in files.items():
            chunks.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n").encode())
            chunks.append(content)
            chunks.append(b"\r\n")
        chunks.append(f"--{boundary}--\r\n".encode())
        body = b"".join(chunks)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "")
            payload = response.read()
            if "json" in content_type:
                return json.loads(payload), payload, content_type
            return None, payload, content_type
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
            code = payload.get("error", {}).get("code", "")
        except Exception:
            code = ""
        safe_messages = {
            "AUTHENTICATION_REQUIRED": "Authentication failed; enter a valid bearer token.",
            "INVALID_INPUT": "The submitted input is invalid.",
            "INVALID_EVIDENCE_BUNDLE": "The evidence bundle failed validation.",
            "AUDIT_TIMEOUT": "The audit reached its configured time limit.",
            "CONCURRENCY_LIMIT": "The local audit service is busy. Try again shortly.",
        }
        message = safe_messages.get(code, "The local API request failed.")
        raise RuntimeError(message) from None
    except (urllib.error.URLError, TimeoutError):
        raise RuntimeError("Cannot reach the configured local API address.") from None


def _display_safe_excerpt(excerpt: str) -> None:
    """Render untrusted evidence as text, never as Markdown or HTML."""
    st.text(excerpt)


def _get_all_incomplete(base: str, audit_id: str, token: str | None = None) -> list[dict]:
    result: list[dict] = []
    offset = 0
    while True:
        page, _, _ = _api_call(base, f"/api/audits/{audit_id}/cases?status=INCOMPLETE&offset={offset}&limit=500", token=token)
        result.extend(page["items"])
        offset += page["limit"]
        if offset >= page["total"]:
            return result


def main() -> None:
    st.set_page_config(page_title="Ghost Data Audit", page_icon="🛡️", layout="wide")
    st.title("Ghost Data Audit")
    st.caption("Local-first deletion audits · deterministic evidence processing · hosted models disabled")

    with st.sidebar:
        st.subheader("Local application")
        base = st.text_input("API address", value=os.environ.get("GHOST_AUDIT_API_URL", "http://127.0.0.1:8000"))
        token = st.text_input("Bearer token (kept in this browser session only)", type="password", key="api_bearer_token")
        st.caption("The token is sent only in the Authorization header and is not written to a file.")
        connection_mode = os.environ.get("GHOST_AUDIT_API_CONNECTION_MODE", "local")
        if classify_api_address(base, connection_mode=connection_mode) == "external":
            st.warning("External API target: uploads and the bearer token are sent server-to-server to this host. Use only a trusted endpoint with authentication and TLS.")
        try:
            version, _, _ = _api_call(base, "/api/version", token=token, timeout=5)
            st.success(f"API {version['version']} · {version['implementation_mode']}")
            st.write(f"Retention: {version['retention_hours']} hours")
            st.caption("Evidence is processed by the configured local application instance.")
        except RuntimeError as exc:
            st.error(str(exc))
        st.divider()
        if "audit_id" in st.session_state:
            st.code(st.session_state.audit_id, language=None)
            if st.button("Forget selected audit", use_container_width=True):
                st.session_state.pop("audit_id", None)
                st.rerun()

    st.header("Start an audit")
    request_file = st.file_uploader("Request CSV", type=["csv"], key="request_csv")
    bundle_file = st.file_uploader("Evidence bundle ZIP", type=["zip"], key="evidence_zip")
    st.caption("Required bundle files: evidence_files.csv, user_identities.csv, user_audit_log.csv, system_activity.csv, and deletion_rules.csv, plus manifest-listed evidence files.")
    st.info("Uploads are processed locally by this application instance. Validate the files before running the audit.")
    c1, c2 = st.columns(2)
    if c1.button("Validate inputs", disabled=not (request_file and bundle_file), use_container_width=True):
        try:
            request_bytes = request_file.getvalue()
            bundle_bytes = bundle_file.getvalue()
            validation, _, _ = _api_call(base, "/api/validate", "POST", token=token, files={
                "request_csv": (request_file.name, request_bytes, "text/csv"),
                "evidence_bundle": (bundle_file.name, bundle_bytes, "application/zip"),
            })
            st.session_state["validated_inputs"] = (request_file.name, bundle_file.name,
                                                       hashlib.sha256(request_bytes).hexdigest(),
                                                       hashlib.sha256(bundle_bytes).hexdigest())
            st.success(f"Inputs valid · {validation['request_count']} requests · {validation['manifest_file_count']} manifest files")
        except RuntimeError as exc:
            st.error(str(exc))
    valid_names = st.session_state.get("validated_inputs")
    request_digest = hashlib.sha256(request_file.getvalue()).hexdigest() if request_file else ""
    bundle_digest = hashlib.sha256(bundle_file.getvalue()).hexdigest() if bundle_file else ""
    can_run = bool(request_file and bundle_file and valid_names == (request_file.name, bundle_file.name,
                                                                    request_digest, bundle_digest))
    if c2.button("Run local audit", disabled=not can_run, type="primary", use_container_width=True):
        try:
            with st.spinner("Auditing locally… this may take several minutes."):
                accepted, _, _ = _api_call(base, "/api/audits", "POST", token=token, files={
                    "request_csv": (request_file.name, request_file.getvalue(), "text/csv"),
                    "evidence_bundle": (bundle_file.name, bundle_file.getvalue(), "application/zip"),
                })
            st.session_state["audit_id"] = accepted["audit_id"]
            st.session_state.pop("validated_inputs", None)
            st.success("Audit completed and output validation passed.")
        except RuntimeError as exc:
            st.error(str(exc))

    audit_id = st.session_state.get("audit_id")
    if not audit_id:
        st.markdown("### Explore results")
        st.write("Upload the included synthetic request CSV and evidence bundle for a safe demonstration.")
        return

    st.divider()
    try:
        record, _, _ = _api_call(base, f"/api/audits/{audit_id}", token=token)
        summary = record.get("summary", {})
        st.header("Audit overview")
        a, b, c, d = st.columns(4)
        a.metric("Requests audited", summary.get("request_count", 0))
        counts = summary.get("status_counts", {})
        b.metric("Complete", counts.get("COMPLETE", 0))
        c.metric("Incomplete", counts.get("INCOMPLETE", 0))
        d.metric("Not applicable", counts.get("NOT_APPLICABLE", 0))
        x, y, z = st.columns(3)
        x.metric("Needs manual review", summary.get("needs_review_count", 0))
        y.metric("Share of incomplete", f"{summary.get('needs_review_percent_of_incomplete', 0)}%")
        z.metric("Validation", summary.get("validation_status", "unknown"))
        st.caption(f"Created {summary.get('created_at')} · duration {summary.get('duration_seconds')} seconds · local status {record.get('status')}")
        st.bar_chart({"Status": list(counts.keys()), "Cases": list(counts.values())}, x="Status", y="Cases")

        _csv_data, csv_bytes, _ = _api_call(base, f"/api/audits/{audit_id}/download", token=token)
        _detail_data, detail_bytes, _ = _api_call(base, f"/api/audits/{audit_id}/detail.json", token=token)
        st.download_button("Download challenge CSV", csv_bytes, "ghost_audit_output.csv", "text/csv")
        st.download_button("Download JSON detail", detail_bytes, "ghost_audit_detail.json", "application/json")

        st.header("Needs-review queue")
        with st.expander(f"{summary.get('needs_review_count', 0)} incomplete cases with empty plans", expanded=bool(summary.get("needs_review_count", 0))):
            if summary.get("needs_review_count", 0):
                st.warning("An empty plan does not mean deletion succeeded. The current evidence may not support safe attribution. Review source records and document the limitation.")
                queue = [case for case in _get_all_incomplete(base, audit_id, token) if case.get("review_label") == "NEEDS_REVIEW"]
                st.dataframe(queue, use_container_width=True, hide_index=True)
            else:
                st.success("No empty incomplete plans in this audit.")

        st.header("Case explorer")
        f1, f2, f3, f4 = st.columns([2, 1, 1, 1])
        case_query = f1.text_input("Search case ID", placeholder="e.g. demo_case_001")
        status = f2.selectbox("Status", ["All", "COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"])
        page_size = f3.selectbox("Rows per page", [10, 25, 50], index=1)
        sort_choice = f4.selectbox("Sort", ["Case ID ↑", "Case ID ↓", "Status ↑", "Status ↓"])
        sort_by = "deletion_status" if sort_choice.startswith("Status") else "case_id"
        sort_order = "desc" if sort_choice.endswith("↓") else "asc"
        if case_query.strip():
            page, _, _ = _api_call(base, f"/api/audits/{audit_id}/cases/{urllib.parse.quote(case_query.strip(), safe='')}", token=token)
            items = [page]
            total = 1
            offset = 0
        else:
            filter_part = "" if status == "All" else "&status=" + status
            page_no = st.number_input("Page", min_value=1, value=1, step=1)
            offset = (int(page_no) - 1) * page_size
            page, _, _ = _api_call(base, f"/api/audits/{audit_id}/cases?offset={offset}&limit={page_size}{filter_part}&sort_by={sort_by}&order={sort_order}", token=token)
            items, total = page["items"], page["total"]
        st.caption(f"Showing {len(items)} of {total} cases · ordered by case ID")
        st.dataframe([{"case_id": item["case_id"], "deletion_status": item["deletion_status"],
                       "review": item.get("review_label") or ""} for item in items], use_container_width=True, hide_index=True)
        choice = st.selectbox("Open case", [item["case_id"] for item in items] or [""])
        if choice:
            case, _, _ = _api_call(base, f"/api/audits/{audit_id}/cases/{urllib.parse.quote(choice, safe='')}", token=token)
            if case.get("review_label") == "NEEDS_REVIEW":
                st.warning("NEEDS_REVIEW — empty plan is not evidence of successful deletion.")
            st.subheader(f"{case['case_id']} · {case['deletion_status']}")
            steps = case.get("steps", [])
            for phase in ("FINDING", "REMEDIATION", "VERIFICATION"):
                phase_steps = [step for step in steps if step["phase"] == phase]
                if phase_steps:
                    st.markdown(f"**{phase.title()}**")
                    st.dataframe(phase_steps, use_container_width=True, hide_index=True)
            references = case.get("evidence_references", [])
            for evidence_id in references:
                with st.expander(f"Evidence {evidence_id}"):
                    preview, _, _ = _api_call(base, f"/api/audits/{audit_id}/evidence/{urllib.parse.quote(evidence_id, safe='')}/preview", token=token)
                    if preview["available"]:
                        st.caption(f"Source: {preview['source_file']}")
                        _display_safe_excerpt(preview["excerpt"])
                    else:
                        st.caption(preview.get("message", "Preview unavailable."))
        st.header("Privacy controls")
        st.write(f"Validated request and evidence inputs are retained for up to {version.get('retention_hours', 24)} hours unless you delete the audit earlier.")
        st.caption("Audit deletion removes retained inputs, output, and structured results from this application directory. It does not erase copies held elsewhere or provide storage encryption.")
        if st.button("Delete this audit and retained files", type="secondary"):
            _api_call(base, f"/api/audits/{audit_id}", "DELETE", token=token)
            st.session_state.pop("audit_id", None)
            st.success("Audit and retained files deleted.")
            st.rerun()
    except RuntimeError as exc:
        st.error(str(exc))


if __name__ == "__main__":
    main()
