# DranzoRMM agent

The endpoint-management agent of DranzoRMM, written in Go. It is a transparent
IT administration tool: it installs as a normal, visible service
("DranzoRMM Agent"), can be removed by an administrator of the device, only
opens outbound connections to its pinned management server, and executes only
commands signed by that server. The wire protocol is `docs/PROTOCOL.md`.

## Requirements

Go 1.27+, `golangci-lint` 2.x. No CGO is needed for any target.

## Build

```sh
make build        # host binary  -> dist/dranzo-agent
make build-all    # windows|darwin|linux x amd64|arm64 -> dist/
```

Version and default trust anchors are stamped with `-ldflags -X`:

```sh
make build-all VERSION=1.2.3 \
  COMMAND_KEYS="prod-2026:<base64 Ed25519 public key>" \
  CA_PEM_FILE=ca.pem
```

`COMMAND_KEYS` is `kid:base64pub[,kid2:base64pub]`. Without compiled-in
anchors the installer must pass `--ca-file` and `--trust-file`.

## Test and lint

```sh
make test         # go test ./... -race -count=1
make lint         # golangci-lint run ./...
make vet-all      # build + vet for all six targets
make check        # gofmt check, vet-all, test, lint
```

Lint the per-OS files too with `GOOS=linux golangci-lint run ./...` and
`GOOS=windows golangci-lint run ./...`.

The end-to-end test (`internal/agentcore/e2e_test.go`) runs the real agent
against an in-process fake server (`internal/testserver`). The Windows and
Linux code paths can be compiled and vetted on any machine, but only executed
on those systems (CI runners).

`internal/protocol/testdata/vectors.json` (signed-envelope interop vectors
from the server's C# signer) is picked up by `TestInteropVectors` when present.

## Run

Production (as root / elevated Administrator):

```sh
dranzo-agent install --server https://rmm.example.com:8443 --token dz_enroll_... \
    [--ca-file ca.pem --trust-file trust.json]
dranzo-agent status
dranzo-agent uninstall [--code XXXX] [--keep-data]
```

The token may also be passed in the `DRANZO_ENROLL_TOKEN` environment variable
(keeps it out of the process list). It is erased from disk after enrollment.

Development, without a service manager and without the real server:

```sh
go run ./cmd/fakeserver --listen 127.0.0.1:8443 --out ./dev-data --demo-job
go run ./cmd/dranzo-agent run --foreground --data-dir ./dev-data
```

`cmd/fakeserver` is a development-only stand-in (throwaway CA and signing key
held in memory). Never deploy it.

## Layout

| Path | Purpose |
|---|---|
| `cmd/dranzo-agent` | CLI: `run`, `install`, `uninstall`, `enroll`, `status`, `version` |
| `internal/protocol` | Envelopes, all payload types, signed-command `Verifier`, `NonceStore`, `SeqTracker` |
| `internal/trust` | `ca.pem` + `trust.json` (pinned CA, command keys) |
| `internal/identity` | Device key, CSR, enroll, renew, atomic certificate switch |
| `internal/transport` | mTLS WebSocket client, reconnect backoff, blob download/upload |
| `internal/jobs` | Job manager, handler registry, output streaming |
| `internal/jobs/script` | The `script` job kind |
| `internal/platform` | Per-OS helpers (console user, run as user, process-tree kill, reboot pending, machine id) |
| `internal/inventory` | `inventory` report collectors and heartbeat statistics |
| `internal/agentcore` | Main loop, message routing, reporters, plug-in interfaces |
| `internal/svc` | Service install / uninstall / run (kardianos/service) |
| `internal/config`, `internal/fsutil` | Data directories, config files, atomic writes, permissions |
| `internal/logging` | JSON logs, rotation, redaction |
| `internal/testserver`, `cmd/fakeserver` | Fake gateway for tests and local development |

OS-specific code lives in `*_windows.go`, `*_darwin.go` and `*_linux.go`
files; parsers of command output are in untagged files and are unit-tested
with fixtures for all three systems.

## Extending

- New job kind: `agent.Jobs().Register("kind", handler)` before `agent.Run`.
- New periodic report: `agent.RegisterReporter(name, interval, collect)`.
- Remote sessions / self-update: `agent.SetSessionHandler(h)` /
  `agent.SetUpdateHandler(h)` with implementations of
  `agentcore.SessionHandler` / `agentcore.UpdateHandler`; `agent.Env()` gives
  them the sender, blob client, platform handle and sequence tracker.
