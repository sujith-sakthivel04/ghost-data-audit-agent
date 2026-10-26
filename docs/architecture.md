# Architecture

## Audit engine

The CLI accepts explicit request and evidence paths and validates their layout. `engine.run_audit()` loads identity snapshots and history, global activity, and the evidence manifest. `EvidenceIndex` parses supported local CSV, JSON, SQL, logs, text, PDFs, and screenshots when optional readers are available. Each observation retains provenance and timestamps. The deterministic engine resolves identifiers, reconstructs state as of each `audit_at`, applies policy, and emits the strict CSV contract. It has no hosted-model or network calls.

## Local application path

`api.create_app()` builds the FastAPI application around `AuditService`. In production or when a bearer token is configured, a constant-time token comparison protects validation, audit creation, results, case lookup, previews, downloads, and deletion. Health and version endpoints expose minimal public status. CORS is disabled unless explicit origins are configured.

The service validates request CSVs and evidence ZIPs, extracts each archive into an isolated audit directory, checks manifest paths, then invokes the existing `python -m ghost_audit run` CLI in a child process with a configurable timeout. Timeout cleanup terminates the child process tree. Output validation must pass before success is published. The web layer does not duplicate candidate retrieval, identity resolution, policy, or step construction.

The service stores a summary, structured case results, output CSV, request CSV, and validated evidence bundle under one random audit ID. Retention defaults to 24 hours; startup and request-time cleanup remove expired directories. The delete endpoint removes the same directory. Failed or timed-out runs lose raw inputs and partial outputs while retaining a small failure record. Evidence previews resolve only manifest-listed file IDs inside that audit's extracted bundle and are rendered as text.

The API processes audits synchronously. A bounded semaphore limits concurrent runs and a subprocess timeout bounds each run, but the process has no hard memory/CPU quota and the HTTP request worker remains occupied during execution. No durable queue, restart recovery, or client cancellation is implemented.

## Dashboard and deployment

`dashboard.py` is a Streamlit client. It accepts the optional shared bearer token in a password control held in session memory and sends it only in Authorization headers. It shows status counts, case results, ordered steps, evidence previews, and a visible `NEEDS_REVIEW` state for incomplete cases with empty plans. An empty plan is not interpreted as successful deletion. In Compose, the dashboard talks to the fixed `http://api:8000` service on `app_internal`; the Compose-only connection marker quiets the external-target warning only for that exact HTTP host and port. The browser uses the loopback ingress URL, not the internal service origin. Any other non-loopback target remains classified as external and warns; the warning does not change authentication.

The app image includes application code and pinned runtime dependencies, local Tesseract, a non-root user, read-only root, explicit temp/data locations, and health checks. Compose attaches only FastAPI and Streamlit to `app_internal` with `internal: true`; neither publishes a host port. Nginx runs as UID/GID 101 on both `app_internal` and a separate bridge named `ingress`. It exposes only `127.0.0.1:8080`, routes `/api/` to the fixed FastAPI service, and routes the remaining paths to Streamlit with WebSocket upgrade support. Its config overwrites forwarding headers from the socket peer, disables access logs, and does not allow arbitrary upstreams or tunneling. The app services have no general egress route through the proxy. The operator must configure secrets externally and provide TLS termination and any remote access controls for remote deployment.

## Security boundaries

Explicit identity/resource links and strong identifiers remain the engine's basis for attribution. Conflicts are rejected; weak temporal clues do not prove ownership. Evidence after a cutoff does not prove earlier state. The web layer passes only validated local inputs to the same engine. It makes no hosted-model or network calls during evidence processing.

Implemented controls cover common path traversal/archive attacks, upload and concurrency bounds, audit-local storage paths, output validation, cleanup, bearer-token authentication, and timeout process-tree termination. These controls are not a malware scanner or a sandbox against a hostile local user. Storage is not encrypted and filesystem deletion is not secure erasure.

## Future durable-work design (not implemented)

If audits need to outlive a synchronous request, add a persistent job table with a unique audit ID, explicit states (`queued`, `running`, `succeeded`, `failed`, `cancelled`), timestamps, bounded attempts, and a durable storage reference. A small worker should claim jobs transactionally, launch an isolated child process with explicit CPU/memory/disk limits, publish output atomically only after validation, and record sanitized errors. Add owner-scoped authorization before exposing multi-user job IDs, cancellation that terminates the process group, retention cleanup for both metadata and files, and restart recovery tests. Do not claim these properties until implemented and tested.
