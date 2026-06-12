package vpp

import (
	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-limiter/internal/binapi/classify"
	"github.com/fivetime/sbw-limiter/internal/binapi/lcp"
	"github.com/fivetime/sbw-limiter/internal/binapi/policer"
)

// RequiredMessages is the set of binary-API messages the edge-agent's
// materializers send. Connect verifies the running VPP is compatible with all
// of them on every (re)connect, so a VPP/binding version drift is caught at
// connect time rather than mid-reconcile. One representative request message
// per plugin is enough — CheckCompatibility validates the CRC of each.
func RequiredMessages() []govppapi.Message {
	return []govppapi.Message{
		// policer (T-402)
		&policer.PolicerAdd{},
		&policer.PolicerDel{},
		&policer.PolicerUpdate{},
		&policer.PolicerBindV2{},
		// classify (T-403/404/405)
		&classify.ClassifyAddDelTable{},
		&classify.ClassifyAddDelSession{},
		&classify.PolicerClassifySetInterface{},
		// linux-cp (T-410)
		&lcp.LcpItfPairAddDelV3{},
	}
}
