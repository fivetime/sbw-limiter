# syntax=docker/dockerfile:1.7
###############################################################################
# sbw-limiter / edge-agent — the L-node agent. Talks to VPP (govpp) over
# /run/vpp/api.sock and to bird over /run/bird.ctl PURELY via sockets — it does
# NOT shell out to vppctl/birdc, so it needs NEITHER bird NOR VPP binaries in its
# image. The ONLY external command it runs is `ip route` (iproute2), for the
# three-way route-count drift check (T-502). So: static Go binary + iproute2.
# NOT based on the bird-vpp image.
#
# Co-location is a DEPLOYMENT concern, not an image one: run this beside the VPP
# (and bird) it drives, sharing /run/vpp (+ the bird socket) via a volume — e.g.
# the same k8s pod (VPP + bird + agent containers) or the compose below.
#
# go.mod replace github.com/fivetime/sbw-contract => ../sbw-contract → clone it.
###############################################################################
FROM golang:1.25-alpine AS builder

ARG LIMITER_REPO=github.com/fivetime/sbw-limiter
ARG LIMITER_REF=main
ARG CONTRACT_REPO=github.com/fivetime/sbw-contract
ARG CONTRACT_REF=main
ARG GH_TOKEN=""
ARG VERSION=dev

RUN apk add --no-cache git ca-certificates
WORKDIR /src
# CACHEBUST (set to the commit SHA in CI) forces this clone layer to re-run on every
# build. Without it the gha cache freezes `git clone -b main` at its first run, so new
# commits to main never reach the image even though it gets a fresh sha-<commit> tag —
# the binary stays frozen while the tag lies. Referencing $CACHEBUST in the RUN makes
# the layer's cache key depend on it, so a per-commit value re-clones the latest source.
ARG CACHEBUST=0
RUN set -eux; \
    echo "cachebust ${CACHEBUST}"; \
    auth=""; [ -n "$GH_TOKEN" ] && auth="x-access-token:${GH_TOKEN}@"; \
    git clone --depth 1 -b "$LIMITER_REF"  "https://${auth}${LIMITER_REPO}.git"  sbw-limiter; \
    git clone --depth 1 -b "$CONTRACT_REF" "https://${auth}${CONTRACT_REPO}.git" sbw-contract

WORKDIR /src/sbw-limiter
# Stamp buildinfo.{Version,Commit} at link time. Commit comes from the ACTUAL
# cloned HEAD (git rev-parse), not the CACHEBUST arg — so `edge-agent -version`
# and the startup log report exactly which commit was compiled (the old
# `-X main.version` targeted a non-existent symbol → silently stayed 0.0.0-dev).
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    COMMIT="$(git rev-parse --short HEAD)"; \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/fivetime/sbw-contract/buildinfo.Version=${VERSION} -X github.com/fivetime/sbw-contract/buildinfo.Commit=${COMMIT}" \
      -o /out/edge-agent ./cmd/edge-agent

###############################################################################
# runtime — alpine + iproute2 (the `ip route` dep) + CA certs. No bird/VPP.
###############################################################################
FROM alpine:3.23
ARG VERSION=dev
LABEL org.opencontainers.image.title="sbw-edge-agent" \
      org.opencontainers.image.description="Shared-bandwidth-pool L-node agent (VPP policer/classify + bird FlowSpec, socket-driven)" \
      org.opencontainers.image.source="https://github.com/fivetime/sbw-limiter" \
      org.opencontainers.image.version="${VERSION}"

RUN apk add --no-cache iproute2 ca-certificates
COPY --from=builder /out/edge-agent /usr/local/bin/edge-agent
# metrics 9102 (edge_id-labelled). Config is via BWPOOL_* env (see compose).
EXPOSE 9102
ENTRYPOINT ["/usr/local/bin/edge-agent"]
