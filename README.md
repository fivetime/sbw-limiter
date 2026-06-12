# sbw-limiter(项目 B / L)

共享带宽池限速系统的**限速节点**:bird-vpp 底座(BIRD 3.3 + VPP 26.06 + linux-cp)+ **policer/classify 共享桶限速** + **Go edge-agent**(被 controller 驱动、渲染 BIRD include、govpp 下发、健康上报、三方对账)。设计见 `DESIGN-limiter-node.md` / 总纲 `DESIGN-topology.md`。

- `internal/vpp` —— govpp 物化(policer/classify/lcp/interface)。
- `internal/agent` —— reconcile 主循环、对账、fail-static、VPP 重启恢复。
- `internal/bird`/`birdconf`/`anchors`/`leakcheck` —— BIRD 控制面物化与锚定泄漏自检。
- `internal/accounting` —— 三方路由计数对账。

> **出向归位(ABF)不在本仓**:已移交 R / bird-vpp(项目 A,收 FlowSpec→VPP ABF)。本仓只做限速结算 + 控制面通告。

`make ci` 跑全套。集成测试 `-tags integration`(真实 VPP/BIRD,经 `BWPOOL_TEST_*` 环境变量)。
