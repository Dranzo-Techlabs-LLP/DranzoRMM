# DranzoRMM: working conventions

Read `docs/SPEC.md` (the brief), `docs/ARCHITECTURE.md` and `docs/PROTOCOL.md` before changing anything. `docs/PLAN.md` tracks phase progress.

## Non-negotiable
- Security first: this system can run code on every client device. Every feature that runs code or opens a session ships with its **authorization check, audit event and tests in the same change**.
- Agent transparency rules in `docs/SPEC.md` §1 (visible service, removable, no hiding, no AV evasion, visible session indicator). If a request conflicts, flag it; do not implement it.
- Never commit secrets, signing keys or customer data. Dev keys live in `~/.dranzormm-dev/` (outside the repo). `.env.example` only.
- No hand-written cryptography. Use the BCL / BouncyCastle (server) and the Go standard library (agent).
- Changes to sections 6 and 8 of the brief (protocol, security design) need the owner's sign-off first. Update `docs/PROTOCOL.md` before the code.

## Layout
- `agent/`: Go module `github.com/dranzo/dranzormm/agent`. One package per concern under `internal/`. OS-specific code in `_windows.go` / `_darwin.go` / `_linux.go` files (build tags), never `runtime.GOOS` checks in logic. Parsers are pure functions in untagged files with fixture tests.
- `server/`: `Dranzo.Domain` (entities, permissions) ← `Dranzo.Infrastructure` (EF Core, PKI, signing, storage, audit) ← `Dranzo.Api` (endpoints in `Features/`, agent gateway in `Agents/`, jobs in `Jobs/`, hosted services in `Services/`), tests in `tests/Dranzo.Tests`.
- `web/`: React + TypeScript + Vite, features under `src/features/<area>`.

## Server rules
- Every endpoint declares **one** of `.RequirePermission(...)`, `.AuthenticatedOnly()`, `.Anonymous()`, `.AgentListener()`. `EndpointAccessTests` fails otherwise.
- Tenant isolation is central: every entity implements a tenancy interface from `Dranzo.Domain/Tenancy.cs` (or is listed in `DranzoDbContext.GlobalEntities`) and gets a global query filter. Endpoints load rows through the filtered context so out-of-scope ids are `404`. Use `IgnoreQueryFilters()` only in auth code, the agent gateway and background services, always with an explicit partner/device predicate, and say why in a comment.
- Load first, validate second (so a foreign id is `404`, not `400`).
- New route family ⇒ add an organization-B resource to `tests/Dranzo.Tests/Infra/CrossTenantIds.cs`.
- Everything that acts on a device is a **job kind** dispatched by `JobDispatcher` (signed at send time). Do not send ad-hoc commands to agents.
- Agent input is untrusted: read it with the `J` helpers (`Agents/CoreProcessors.cs`), bound sizes, and always check `run.DeviceId == conn.DeviceId`.
- Audit with `Ctx.Audit(...)` / `IAuditLog`. Never put secrets, tokens or script bodies in audit detail (hash them: `ContentSha256`).
- Schema changes: `dotnet ef migrations add <Name> --project src/Dranzo.Infrastructure --startup-project src/Dranzo.Api --output-dir Data/Migrations` (from `server/`).

## Commands
| What | Command |
|---|---|
| Server build + tests | `cd server && dotnet build && dotnet test` (needs PostgreSQL; `DRANZO_TEST_PG` overrides `Host=localhost`) |
| Agent build / test / lint | `cd agent && go build ./... && go test ./... -race && golangci-lint run ./...` |
| Agent cross-compile (6 targets) | `cd agent && make build-all` |
| Web | `cd web && npm ci && npm run lint && npm run typecheck && npm test && npm run build` |
| Full stack locally | `docker compose -f deploy/docker-compose.yml up --build`, then `scripts/e2e.sh` |
| Run server without Docker | see `docs/RUNBOOK.md` |

## Style
- C#: nullable enabled, warnings are errors, file-scoped namespaces, minimal APIs. Go: `gofmt`, `golangci-lint` clean, `log/slog` JSON logs with `device_id` / `job_run_id`. TypeScript: strict, ESLint + Prettier.
- Tests live next to what they test; integration tests run the real server (real Kestrel, real TLS, real PostgreSQL) through `ServerFixture` and a protocol-level `TestAgent`.
- Keep the build green. A phase is not done until builds, tests, `docs/PLAN.md` and `CHANGELOG.md` are updated and committed.
