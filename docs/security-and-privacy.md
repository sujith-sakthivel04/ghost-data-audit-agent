# Security and privacy notes

## Scope and threat model

This single-user portfolio prototype processes uploaded request and evidence bundles on the host. The implementation reduces common unsafe upload, cross-audit path, accidental disclosure, and runaway child-process risks. It does not claim certification or protect against a hostile host administrator, compromised operating system, malicious dependency, or arbitrary resource-exhaustion payload. Review the controls before any deployment.

## Authentication and browser access

API development mode is unauthenticated only when no token is configured and the API should bind to loopback. Configuring `GHOST_AUDIT_BEARER_TOKEN` enables bearer authentication; production mode fails closed unless a token of at least 32 non-whitespace characters is configured. The dashboard accepts a token in a password field, stores it in Streamlit session memory only, and sends it via the Authorization header. Tokens are not placed in URLs or logs. A shared token is not identity, authorization roles, multi-tenancy, or enterprise-grade access control. Health and version endpoints are public and intentionally return minimal data.

CORS is disabled by default. Configured origins must be explicit HTTP(S) origins; `*` is rejected. CORS is a browser policy, not authentication. Compose keeps FastAPI and Streamlit only on the `app_internal` network (`internal: true`). A pinned Nginx reverse proxy is the only service on the separate `ingress` bridge and publishes only `127.0.0.1:8080`. It routes `/api/` to the fixed API service and all other paths to Streamlit; it is not a generic forward proxy. The dashboard's server-side API target is the fixed `http://api:8000` service origin, which Compose marks as internal. That narrow marker suppresses the dashboard's generic external-target warning only for that exact internal URL; loopback targets are recognized by parsed hostname/IP, and arbitrary non-loopback targets still warn. It does not bypass bearer authentication. The API still enforces bearer authentication on sensitive routes. Loopback binding is for local use, not a complete public-deployment security solution; remote deployment requires TLS termination and additional network controls.

## Uploads and execution

The service limits each upload, ZIP entry count, total extracted bytes, concurrent audits, and execution time. It rejects absolute/traversal paths, ZIP-slip entries, symbolic links, encrypted archive members, duplicate paths, unsupported extensions, missing required files, malformed manifests, invalid timestamps, and manifest paths outside the extracted bundle. Extraction checks real destination paths and size while writing. Each audit has a random isolated storage directory. Evidence previews are restricted to the selected audit's manifest and displayed as escaped text.

The engine runs as a child process with a fixed working directory and bounded timeout. Timeout handling terminates the process tree. Failed execution or output validation does not publish success, and failed raw inputs and partial output are cleaned up. The API is synchronous and uses a bounded concurrency semaphore. This controls simultaneous work but is not memory/CPU isolation; no operating-system resource quota is applied.

The parser is not a malware scanner or full sandbox. File parser libraries and OCR tools process untrusted inputs within the service process/child boundary. Do not upload bundles from untrusted parties to a publicly reachable instance without additional isolation and review.

## Storage, logs, deletion, and retention

Request data, evidence, outputs, and structured results are retained under `GHOST_AUDIT_DATA_DIR`, for 24 hours by default. Expired audits are deleted at service startup and API access; a user can request earlier deletion. Deletion removes filesystem entries only. It is not cryptographic erasure and does not remove backups, snapshots, filesystem journal copies, or external downloads. Storage is not encrypted at rest. POSIX storage directories use restrictive permissions where supported; this is not a substitute for encrypted volumes or access controls on the host.

Default logs and API errors avoid raw request contents, evidence contents, identifiers, and bearer secrets. Output rows and evidence references remain sensitive; protect the data directory and downloaded files. Optional diagnostics can contain identifiers and must be protected by the operator.

## Container and CI controls

The app image uses a slim Python base, a constrained runtime dependency set, local Tesseract, UID/GID 10001, read-only roots, temporary filesystems, and a named data volume. The Nginx image is pinned by digest, runs as UID/GID 101, and has a read-only root with temporary storage. API and dashboard have no host-published ports and attach only to `app_internal` (`internal: true`). Only the proxy joins `app_internal` and the normal `ingress` bridge, publishing `127.0.0.1:8080`. The proxy configuration contains fixed upstreams only and access logging is disabled to avoid recording request paths or identifiers. The image build context excludes challenge data, examples, tests, docs, local outputs, traces, virtual environments, caches, and credentials. The synthetic demo mount is read-only and supplied at runtime. The proxy has bridge egress, but application services do not join that network and cannot use the fixed reverse-proxy routes as a general tunnel.

CI runs synthetic tests and a synthetic CLI run in a container with networking disabled. It does not use real customer or challenge data. No vulnerability scan is configured; passing CI is not a security guarantee. Dependency and base-image updates still require review.

## Outstanding controls

Not implemented: encrypted storage, secure/cryptographic erasure, identity-aware or role-based access control, multi-tenant authorization, TLS termination, rate limiting, malware scanning, hard CPU/memory isolation, durable background jobs, cancellation, centralized monitoring, automated vulnerability scanning, external security review, backup policy, and recovery testing. The synchronous API can remain occupied until an audit completes or reaches its configured timeout. Do not describe this application as production-ready or certified.
