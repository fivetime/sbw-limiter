// Package agent hosts edge-agent logic: the BIRD control-socket client and
// anchors renderer, VPP materialization via govpp (policer/classify/ABF/uRPF),
// and the 60s reconciliation loop with three-way accounting. See DESIGN.md §7.
package agent
