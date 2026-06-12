GO ?= go
COMMIT := $(shell git -C $(CURDIR) rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/fivetime/sbw-contract/buildinfo.Commit=$(COMMIT)

.PHONY: all build build-arm64 test vet lint ci tidy clean gen-binapi
all: vet test build
ci: ; bash scripts/ci.sh
lint: ; golangci-lint run --timeout 5m
build: ; $(GO) build -ldflags '$(LDFLAGS)' ./...
build-arm64: ; mkdir -p dist; GOOS=linux GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o dist/edge-agent-arm64 ./cmd/edge-agent
test: ; $(GO) test ./...
vet: ; $(GO) vet ./...
tidy: ; $(GO) mod tidy
clean: ; rm -rf dist
