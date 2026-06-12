package binapi_test

// Compile-time assertions that the message types the agent materializers
// depend on exist with the expected names in the generated bindings. If a
// regeneration drops or renames one of these, this test fails to compile —
// a fast signal that a materializer needs updating.

import (
	"testing"

	"github.com/fivetime/sbw-limiter/internal/binapi/classify"
	"github.com/fivetime/sbw-limiter/internal/binapi/lcp"
	"github.com/fivetime/sbw-limiter/internal/binapi/policer"
)

var (
	// policer (T-402): create/update/delete + worker bind for §5.2 precision.
	_ = policer.PolicerAdd{}
	_ = policer.PolicerDel{}
	_ = policer.PolicerUpdate{}
	_ = policer.PolicerBindV2{}

	// classify (T-403/T-404/T-405): tables, sessions, interface attach.
	_ = classify.ClassifyAddDelTable{}
	_ = classify.ClassifyAddDelSession{}
	_ = classify.PolicerClassifySetInterface{}

	// lcp / linux-cp (T-410): interface pair management.
	_ = lcp.LcpItfPairAddDelV3{}
)

func TestBindingsLink(t *testing.T) {
	// The var block above is the real assertion; this keeps `go test` honest.
	pa := policer.PolicerAdd{}
	if pa.GetMessageName() == "" {
		t.Fatal("policer_add has no message name")
	}
	cs := classify.ClassifyAddDelSession{}
	if cs.GetMessageName() == "" {
		t.Fatal("classify_add_del_session has no message name")
	}
}
