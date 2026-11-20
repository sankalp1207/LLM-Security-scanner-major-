# Android integration plan

## Repository findings (verified from implementation)

The backend is FastAPI (`app/main.py`) with `/api/v1` routers, SQLAlchemy persistence, and a Streamlit web console. The Android client is a separate Kotlin/Compose application. The client must never run scanner, detector, remediation, or LLM-provider logic locally.

### Authentication

All project, scan, finding, Copilot, remediation, and report operations use `get_current_user_id` (`app/api/auth.py`). Development/test mode accepts optional `X-User-ID` (default identity `default_user`); this is explicitly not authentication. Production requires an HS256 JWT in `Authorization: Bearer <token>` with `sub` and unexpired `exp`, signed using server `JWT_SECRET_KEY` (minimum 32 characters). The repository does not implement account registration, login, access-token issuance, refresh, or logout endpoints. Android therefore accepts a backend-issued bearer token and stores it encrypted; it cannot issue or refresh one. A local development identity header is supported as a separate opt-in development setting only.

## Implemented API surface

All paths below are prefixed by `/api/v1`; except public health and preset routes, the API requires the user identity described above.

| Capability | Routes and verified contract |
|---|---|
| Health | `GET /health` returns status, environment, version, timestamp, and component statuses. |
| Presets | `GET /scans/presets` (also `/scan/presets`) returns canonical preset objects (`preset_id`, `name`, `description`, `enabled_categories`, server limits and authorization requirement). Presets are quick_scan, full_scan, deep_red_team. |
| Projects | `GET /projects?skip&limit&include_archived` returns `{total, items}`. `GET /projects/{id}` returns project metadata and safe target configuration (credential is masked). `POST /projects` creates, `PATCH /projects/{id}` updates, `DELETE /projects/{id}` deletes. `GET/PATCH /projects/{id}/preferences` manages preferences. `POST /projects/{id}/verify-connection` runs target diagnostics. `GET /projects/{id}/scan-capabilities` returns target capability report. |
| Project scans | `POST /projects/{id}/scans` accepts `ProjectScanCreateRequest` (`preset`, optional categories/limits/fuzzing, `external_target_authorized`, `sync_execute`) and returns `ScanResponse`. `GET /projects/{id}/scans` returns `{total, items}`. |
| Scans | `GET /scans?skip&limit`, `POST /scans` (legacy direct scan request), `GET /scans/{id}`, `GET /scans/{id}/tests`, `GET /scans/{id}/findings`, `POST /scans/{id}/cancel`, `GET /scans/{id}/progress`, `GET /scans/{id}/events?since_seq&limit&event_type`, `GET /scans/{id}/live?since_seq`. `ScanResponse` contains lifecycle status, counts, summary and failure/cancellation reason. Progress contains backend-computed percentage, test counts, category, latest sequence and severity breakdown. |
| Findings | `GET /findings?skip&limit&category&severity&retest_status`, `GET /findings/{id}`, `POST /findings/{id}/retest`, `POST /findings/{id}/remediation`. Finding response includes title, category, severity, description, evidence, target, test case, detection, remediation, timestamp and retest status. |
| Copilot | `POST /copilot/conversations` (`title`, optional `project_id`), `GET /copilot/conversations`, `GET /copilot/conversations/{id}`, `DELETE /copilot/conversations/{id}`, `POST /copilot/conversations/{id}/messages` (`content`, optional project/finding/scan IDs), `GET /copilot/conversations/{id}/messages`, `POST /copilot/explain-finding/{finding_id}`, `POST /copilot/compare-scans`. Message endpoint returns a persisted response object; streaming is not implemented. |
| Remediation | `POST /remediations/findings/{finding_id}`, `GET /remediations/{id}`, `POST /remediations/{id}/generate-fix`, `GET /remediations/{id}/patches`, `GET /remediations/patches/{id}`, `POST /remediations/patches/{id}/validate`, `/approve`, `/reject`, `/apply`, `POST /remediations/{id}/verify`, `/rollback`, `GET /remediations/projects/{project_id}/history`, and `GET /remediations/patches/{id}/download`. Applying/rollback changes the authorized backend workspace and must have an explicit confirmation in the client. |
| Reports | `GET /scans/{id}/report` returns structured JSON `ScanReportResponse`; `GET /scans/{id}/export.csv` returns sanitized CSV. No PDF endpoint exists. |
| Other existing APIs | Detection (`POST /detect`), dataset/suite management, onboarding, demo RAG. These are not needed for the initial mobile workflow. |

### Request/response details

Scan preset request example: `{"preset":"quick_scan","external_target_authorized":false,"sync_execute":false}` to `POST /projects/{id}/scans`. Deep red-team preset requires the explicit authorization acknowledgement (`requires_authorization_ack=true` from the preset response). The server owns actual test selection, limits, and execution. Project creation accepts `name`, `description`, `application_type`, `environment`, `target_type`, and optional target configuration. Copilot message content is 1–4000 characters. Report and finding field definitions are in `app/schemas/{scans,projects,copilot,reports}.py`.

## Real-time monitoring

The backend implements standard Server-Sent Events at `GET /scans/{id}/live?since_seq=N` (`text/event-stream`, `id`, `event`, JSON `data`, heartbeat comments). It replays history after the sequence cursor and then emits live events. `GET /events?since_seq=N` recovers history; `GET /progress` is the persisted-state polling fallback. Android uses an authenticated OkHttp stream with a monotonic cursor, deduplicates by sequence, reconnects, and falls back to bounded polling if SSE fails. The backend has no WebSocket route. Background work is not promised to continue in Android; reopening monitoring recovers from server history/progress.

## Mobile architecture and scope

Single application module under `android/`, package `com.llmsecurityscanner`: Compose Material 3 UI and navigation; screen state in ViewModels/StateFlow; Retrofit/Gson API DTOs; OkHttp auth and SSE; repository boundary; Android Keystore AES-GCM encrypted token preferences; Room cache for server-fetched projects/scans/findings; editable backend URL; no secrets or user credentials in source. UI focuses on dashboard, projects, scan setup/monitoring, findings/detail, Copilot, JSON/CSV reports, and settings.

## Unsupported backend features and smallest follow-up

* Native login/registration/refresh: add a server-owned identity-provider flow or documented JWT issuance endpoint before claiming login. Until then Android can use a JWT issued by the deployment's trusted auth system. No mobile-specific backend change is required for this integration.
* Attack replay/history/variation execution: no replay routes or replay models were found. Smallest backend addition is an owner-scoped replay create/list/detail contract tied to a finding/test, with persisted status and authorization checks. Android must not fabricate it.
* PDF report generation/download: only JSON and CSV routes exist. Add a server-side PDF renderer and owner-scoped authenticated endpoint if needed.
* Copilot token streaming: current message route returns a completed response. Add an authenticated SSE route only if streaming is required; current mobile chat uses the existing request/response route.
* Aggregate dashboard endpoint: not present. Android derives counts from actual paginated project/scan/finding responses and labels unavailable counts when pagination prevents a complete total; no fabricated trends.

No backend files are changed by this integration.
