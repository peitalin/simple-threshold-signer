# Dashboard Requirements Plan

## Server-side requirements

### 1) Wallets data and query APIs
- Provide paginated wallet listing APIs with: wallet ID, address, chain, owner/user ID, policy ID, balance, status, and timestamps.
- Support high-cardinality filtering and sorting: chain, status, policy, key quorum, wallet type (EOA/smart), and last activity.
- Provide text search across wallet address, wallet ID, user ID, and external reference ID.
- Search and list performance target: p95 < 500ms for standard org-level filters.

### 2) Policy engine and authorization
- Store versioned policy definitions for threshold wallets.
- Enforce policy constraints at transaction-evaluation time:
  - allowed actions (transfer/swap/approve/contract call/key export)
  - allowed chains and environments
  - transaction and daily value limits
  - contract + method allowlists
  - approval requirements (MFA/admin/quorum)
- Support policy simulation endpoint that evaluates a proposed transaction without execution.
- Audit all policy CRUD and policy assignment changes.

### 3) Gas sponsorship and smart wallet controls
- Expose config APIs for sponsorship toggles (global, environment, policy-level).
- Track sponsorship budgets and usage per chain/app/environment.
- Support smart wallet feature flags and deployment configuration.
- Return spend telemetry and failure diagnostics for sponsored transactions.

### 4) App settings and security configuration
- Persist per-environment app settings:
  - allowed origins/domains
  - httpOnly cookie mode
  - JWT issuer/audience/signing key metadata
  - session TTL and refresh policies
- Provide secure validation for origins/domains and wildcard patterns.
- Support optional IP allowlists and admin SSO metadata (OIDC/SAML).

### 5) Key export controls
- Enforce export policy mode: disabled, approval required, allowed with restrictions.
- Restrict exports by role, chain, wallet type, and environment.
- Require step-up checks (MFA + approval reason) when configured.
- Record immutable export audit events with actor, target wallet, and approval path.

### 6) API key management
- Create/revoke/rotate API keys with scopes and environment restrictions.
- Store key metadata: creator, last used, allowed IP ranges, status.
- Return secret only once at creation time; never re-expose plaintext secret.
- Provide stale key detection and usage anomaly signals.

### 7) Webhooks platform
- Support event subscriptions for wallet, policy, auth, and transaction lifecycle events.
- Sign webhook payloads with per-endpoint secrets.
- Implement retry with exponential backoff, dead-letter handling, and replay.
- Provide delivery log APIs with status, attempts, and response payload excerpts.

### 8) RBAC, auditability, and observability
- RBAC roles: Owner, Admin, Security Reviewer, Analyst, Read-only.
- Enforce least-privilege authorization on all write operations.
- Maintain immutable audit logs for all sensitive changes.
- Provide operational telemetry: API latency, signing latency, webhook failure rate, policy enforcement errors.

## Frontend requirements

### 1) Wallets list UX
- Render a wallet table with key columns: wallet, chain, owner, policy, balance, and status.
- Include KPI cards: total assets, wallet count, funded wallets, and volume summary.
- Provide empty, loading, and error states for all table views.
- Support row actions: view details, freeze/unfreeze, reassign policy, export activity.

### 2) Search and filtering UX
- Single search field for wallet address/ID/user ID.
- Filter controls for chain, policy, key quorum, wallet type, status, and date range.
- Support saved views and URL-synced filter state.
- Preserve state across refresh/navigation where possible.

### 3) Policy management UI
- Policy list page with status, scope, and last modified metadata.
- Policy editor with explicit sections for actions, chain rules, limits, and approvals.
- Simulation panel to test sample transactions before publish.
- Change history and rollback affordance on each policy version.

### 4) Gas sponsorship and smart wallet UI
- Dedicated settings panel for sponsorship toggles and budget controls.
- Smart wallet section for deployment mode and account abstraction config.
- Show usage charts and warnings for budget exhaustion/failures.

### 5) App settings UI
- Environment switcher (Dev/Staging/Prod) with clearly separated configuration context.
- App settings forms for origins/domains, cookies, JWT fields, and session policy.
- Validation/error messaging for risky settings (e.g., overly broad origin rules).

### 6) Export key settings UI
- Clear export mode selector with risk labels.
- Approval workflow views for pending export requests.
- Detailed export activity log with filters and event drill-down.

### 7) API key management UI
- Key inventory page showing scope, owner, created date, last used, and status.
- Key creation modal with scope selection and one-time secret reveal UX.
- Rotation/revocation actions with confirmation and impact messaging.

### 8) Webhooks UI
- Endpoint list with active/inactive status and event subscriptions.
- Endpoint editor for URL, signing secret, and retry preferences.
- Delivery logs table with inspect/replay actions.

### 9) Cross-cutting frontend expectations
- Responsive dashboard layout for desktop and laptop widths first, then mobile fallback.
- Role-aware UI states (hide or disable restricted actions based on RBAC grants).
- Consistent patterns for loading, validation, toasts, and destructive confirmations.
- Accessible keyboard navigation and semantic labels for all critical controls.
