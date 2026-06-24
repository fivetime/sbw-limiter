# sbw-limiter

`sbw-limiter` 是共享带宽池系统的 edge-agent 项目，运行在 L 节点上。它从 controller 接收期望状态，把 pool 限速规则物化到 VPP，把 anchors/FlowSpec 物化到 BIRD，并向 controller 上报健康、容量、applied version 和计量/漂移信号。

出向归位的 ABF 不在本仓实现。当前架构中，L 通过 BIRD 发布 FlowSpec，R / bird-vpp 消费标准 BGP FlowSpec 并在 R 侧落 ABF。

## 运行职责

- 连接 controller gRPC，注册 edge、订阅 desired state、发送 `EdgeReport`。
- 维护 fail-static：controller 不可达时保留最后一次有效期望状态，不主动清空数据面。
- 将 `PolicerSpec` 和 `ClassifySession` 物化到 VPP policer/classify，共享桶限速。
- 将 `Anchor` 和 `FlowRedirect` 渲染成 BIRD include，并用 check/configure/rollback 方式应用。
- 通过 reconcile loop 自愈 VPP 重启、规则漂移和 in-memory index 丢失。
- 可选读取 VPP stats segment，把 policer 计量样本推送到 Kafka/Redpanda。
- 可选发布/撤销 canary route，配合 controller 识别软死。

## 关键目录

- `cmd/edge-agent/`：edge-agent 进程入口。
- `internal/agent/`：desired store、reconcile 主循环、delta apply、health、report、metering。
- `internal/grpcclient/`、`internal/homing/`：agent 侧 gRPC client 和多 controller re-home。
- `internal/vpp/`：govpp 物化 policer、classify、interface、stats。
- `internal/anchors/`、`internal/flowspec/`、`internal/bird/`：BIRD include 渲染和 reload。
- `internal/accounting/`：路由/计数对账辅助。
- `internal/binapi/`：VPP binary API generated bindings。
- `deploy/systemd/`、`deploy/vpp/`、`docker/`、`configs/`：部署示例。

## 外部依赖

- Go 1.25。
- `sbw-contract`，本地开发通过 `../sbw-contract` replace。
- VPP 26.06 兼容的 binary API socket，默认 `/run/vpp/api.sock`。
- VPP stats socket，默认 `/run/vpp/stats.sock`，仅计量启用时需要。
- BIRD control socket，默认 `/run/bird.ctl`，启用 anchors/FlowSpec apply 时需要。
- 可选 Kafka/Redpanda，用于计量外送。

## 配置

配置加载顺序为默认值、JSON 文件、`BWPOOL_*` 环境变量。常用字段：

- `edge_id` / `BWPOOL_EDGE_ID`：必填，edge 的稳定逻辑 ID。
- `controller_endpoint` / `BWPOOL_CONTROLLER_ENDPOINT`：单 controller 地址。
- `controller_endpoints` / `BWPOOL_CONTROLLER_ENDPOINTS`：bootstrap controller 列表，逗号分隔。
- `capacity_bps` / `BWPOOL_CAPACITY_BPS`：edge NIC 线速，controller 使用其 90% 作为售卖容量。
- `vpp_api_socket` / `BWPOOL_VPP_API_SOCKET`：VPP binary API socket。
- `bird_socket_path` / `BWPOOL_BIRD_SOCKET`：BIRD control socket。
- `bird_anchors_include` / `BWPOOL_BIRD_ANCHORS_INCLUDE`：agent 管理的 anchors include。
- `bird_flowspec_include` / `BWPOOL_BIRD_FLOWSPEC_INCLUDE`：agent 管理的 FlowSpec include。
- `policer_interfaces` / `BWPOOL_POLICER_INTERFACES`：需要挂 policer-classify chain 的 VPP 接口。
- `metrics_listen_addr` / `BWPOOL_METRICS_LISTEN_ADDR`：Prometheus `/metrics`。
- `canary_include`、`canary_prefix`、`canary_lc`：软死 canary 配置。
- `metering_enable` 和 `METERING_*` 环境变量：Kafka 计量外送配置。

示例配置在 [configs/agent.example.json](configs/agent.example.json)。

## 本地运行

有真实 VPP/BIRD 环境时：

```bash
go run ./cmd/edge-agent -config configs/agent.example.json
```

只做 VPP socket smoke 可使用 `docker/`：

```bash
cd docker
CONTROLLER_ENDPOINTS=host.docker.internal:1791 docker compose up --build
```

这个 compose 只覆盖 VPP/policer 半边；完整 L 节点还需要 BIRD 配置和 include 路径。

## Desired State 路径

controller 推送两类主要指令：

- `DESIRED_STATE`：完整 per-edge 快照，用于冷启动、重连、drift resync 和兜底恢复。
- `DESIRED_DELTA`：按 pool 变化的增量热路径，用于减少大规模 pool 变更时的 O(N) 重渲染。

agent 接收后写入 `DesiredStore`，唤醒 reconcile。VPP 规则由 `internal/agent` 和 `internal/vpp` 物化；BIRD anchors/FlowSpec 由 `BirdApplier` 使用 atomic write、`birdc configure check`、reload、rollback 纪律应用。

## Fail-static 与自愈

- 从未收到 desired state 时，reconcile 会跳过，不会把存活的数据面清空。
- controller 断开后，agent 继续收敛到最后一次有效 desired state。
- VPP 重启后，agent 会重连并重建 policer/classify。
- BIRD control socket 断开后，BIRD client 会在下一次 apply 时重新连接。

## 测试

```bash
go test ./...
go vet ./...
make ci
```

集成测试需要真实 VPP/BIRD，并通过 `BWPOOL_TEST_*` 环境变量指向测试环境：

```bash
go test -tags integration ./...
```

## 运行注意事项

- agent 到 controller 的 gRPC 当前默认明文传输，生产环境应限制管理网络访问或使用外层 mTLS/认证。
- `SIGUSR1` 当前会触发软死 chaos 注入，用于演练 canary/healthDead/failover 链路；生产环境应通过进程权限或后续配置开关限制。
- 启用 Kafka 计量时，建议使用 SASL_SSL 和明确 CA；`kafka_tls_insecure` 只应用于测试环境。
- BIRD include 文件应只由 agent 管理，不要人工编辑；手工修改可能在下一次 reconcile 时被覆盖。
