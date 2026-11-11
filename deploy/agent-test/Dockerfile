# Linux test agent for local development and the end-to-end test. Build context: the repository root.
# Runs the real agent in the foreground (no service manager in a container).
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X github.com/dranzo/dranzormm/agent/internal/buildinfo.Version=0.1.0-dev" -o /out/dranzo-agent ./cmd/dranzo-agent

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates procps && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/dranzo-agent /usr/local/bin/dranzo-agent
COPY deploy/agent-test/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
