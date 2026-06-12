#!/usr/bin/env bash
# CI pipeline (T-202): the single source of truth for checks. The GitHub
# Actions workflow and local `make ci` both run this script, so green local
# means green CI.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "files need gofmt:" >&2
  echo "$unformatted" >&2
  exit 1
fi

step "go vet"
go vet ./...

step "golangci-lint"
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run --timeout 5m
elif [ "${CI:-}" = "true" ]; then
  echo "golangci-lint is required in CI but not installed" >&2
  exit 1
else
  echo "golangci-lint not installed locally; skipping (CI enforces it)" >&2
fi

step "go test (race + coverage)"
# Exclude generated VPP bindings (internal/binapi/<plugin>) from the coverage
# denominator; they are compiled by `go build` and `go vet` below. The
# internal/binapi assertion test is kept.
pkgs=$(go list ./... | grep -v '/internal/binapi/')
go test -race -coverprofile=coverage.out $pkgs
go tool cover -func=coverage.out | tail -1

step "go build"
go build ./...

step "ARM64 release artifacts (edge target)"
mkdir -p dist
commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
ldflags="-X github.com/fivetime/sbw-contract/buildinfo.Commit=${commit}"
GOOS=linux GOARCH=arm64 go build -ldflags "$ldflags" -o dist/edge-agent-linux-arm64 ./cmd/edge-agent
ls -l dist/

printf '\nCI pipeline passed.\n'
