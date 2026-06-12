# systemd units (T-504)

Service units for the two long-lived daemons, per DESIGN.md §7.

| Unit | Binary | Key deps | Notes |
|------|--------|----------|-------|
| `bwpool-edge-agent.service` | `bwpool-edge-agent` | `Requires=vpp.service`, `After=vpp.service bird.service network-online.target` | Programs VPP + BIRD; runs on every edge. |
| `bwpool-controller.service` | `bwpool-controller` | `After=network-online.target` | Control plane; no VPP/BIRD dependency. |

Both use `Restart=always` + `StartLimitIntervalSec=0` so a crash (or a flapping
data plane) is always brought back, and `Type=exec` so systemd tracks start
accurately. The daemons catch `SIGTERM` and exit 0, so `systemctl stop` is a
clean stop, not a failure.

> The agent's data-plane wiring (reconcile loop, route audit, anchor reloader)
> lands in a later task; today the daemon idles after startup. The **unit
> lifecycle** (start / crash-restart / clean stop / boot autostart) is already
> real and verified.

## Install

```sh
sudo deploy/systemd/install.sh both      # or: edge | controller
sudoedit /etc/bwpool/edge-agent.env      # set BWPOOL_EDGE_ID
sudo systemctl enable --now bwpool-edge-agent.service
```

Config is supplied via `EnvironmentFile` (`/etc/bwpool/*.env`); every variable
is `BWPOOL_`-prefixed (see `internal/config`). The agent **requires**
`BWPOOL_EDGE_ID`.

## Dependency on vpp.service / bird.service

The agent unit references `vpp.service` and `bird.service`. Production hosts ship
those (VPP's packaged unit; a BIRD unit). `Requires=vpp.service` means the agent
will not run without VPP and is stopped if VPP is; `bird.service` is `After`-only
so a BIRD restart does not tear the agent down.

## Verify (on a systemd host)

```sh
sudo deploy/systemd/verify.sh
```

Installs stub `vpp.service` / `bird.service` (so the dependency graph resolves
without a real VPP), then checks: start → active (and `Requires=` pulls VPP up),
`systemd-analyze verify` ordering, `SIGKILL` → restart with a new PID, `enable` →
`is-enabled`, and a graceful `stop` (`Result=success`). Self-cleaning.
