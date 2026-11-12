# DranzoRMM agent - build, test and lint.

GO        ?= go
VERSION   ?= 0.1.0-dev
MODULE    := github.com/dranzo/dranzormm/agent
BUILDINFO := $(MODULE)/internal/buildinfo
DIST      ?= dist
TARGETS   := windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

# Default trust anchors can be compiled in (see README):
#   make build-all VERSION=1.2.3 COMMAND_KEYS="kid:base64pub" CA_PEM_FILE=ca.pem
COMMAND_KEYS ?=
CA_PEM_FILE  ?=
CA_PEM_B64   := $(if $(CA_PEM_FILE),$(shell base64 < $(CA_PEM_FILE) | tr -d '\n'),)

LDFLAGS := -X $(BUILDINFO).Version=$(VERSION) \
           -X $(BUILDINFO).EmbeddedCommandKeys=$(COMMAND_KEYS) \
           -X $(BUILDINFO).EmbeddedCAPEMBase64=$(CA_PEM_B64)

.PHONY: all build build-all vet vet-all test lint fmt fmt-check check clean

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/dranzo-agent ./cmd/dranzo-agent

# Static binaries for the six supported targets.
build-all:
	@set -e; for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; [ "$$os" = windows ] && ext=".exe"; \
		echo "build $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST)/dranzo-agent-$$os-$$arch$$ext ./cmd/dranzo-agent; \
	done

vet:
	$(GO) vet ./...

# Compile and vet every package (tests included) for every target.
vet-all:
	@set -e; for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "build+vet $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build ./...; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) vet ./...; \
	done

test:
	$(GO) test ./... -race -count=1

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

check: fmt-check vet-all test lint

# Removes the default output directory only.
clean:
	rm -rf ./dist
