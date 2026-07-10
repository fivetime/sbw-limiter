package vpp

import (
	"reflect"
	"strings"
	"time"

	govppapi "go.fd.io/govpp/api"
)

// fakeChannel is a govppapi.Channel that records every request message and
// replies from a scripted queue. It lets materializer tests assert the exact
// typed messages sent (field encoding) without a real VPP or byte decoding.
type fakeChannel struct {
	sent    []govppapi.Message
	replies []replyFn // one per request, in order
	idx     int
}

// replyFn populates the caller's reply message and/or returns an error.
type replyFn func(reply govppapi.Message) error

func newFakeChannel(replies ...replyFn) *fakeChannel {
	return &fakeChannel{replies: replies}
}

func (c *fakeChannel) SendRequest(msg govppapi.Message) govppapi.RequestCtx {
	c.sent = append(c.sent, msg)
	var fn replyFn
	if c.idx < len(c.replies) {
		fn = c.replies[c.idx]
	}
	c.idx++
	return &fakeRequestCtx{fn: fn}
}

func (c *fakeChannel) SendMultiRequest(govppapi.Message) govppapi.MultiRequestCtx { return nil }
func (c *fakeChannel) SubscribeNotification(chan govppapi.Message, govppapi.Message) (govppapi.SubscriptionCtx, error) {
	return nil, nil
}
func (c *fakeChannel) SetReplyTimeout(time.Duration)               {}
func (c *fakeChannel) CheckCompatiblity(...govppapi.Message) error { return nil }
func (c *fakeChannel) Close()                                      {}

// lastSent returns the most recent request, or nil.
func (c *fakeChannel) lastSent() govppapi.Message {
	if len(c.sent) == 0 {
		return nil
	}
	return c.sent[len(c.sent)-1]
}

type fakeRequestCtx struct{ fn replyFn }

func (r *fakeRequestCtx) ReceiveReply(reply govppapi.Message) error {
	if r.fn != nil {
		if err := r.fn(reply); err != nil {
			return err
		}
	}
	// Mirror the REAL govpp channel (core/channel.go): ReceiveReply itself reflects
	// the Retval field of any *_reply message and returns VPPApiError on non-zero.
	// The production code relies on that (exec has no manual Retval check), so a
	// test that scripts a non-zero Retval must see the same error the real channel
	// would produce.
	if strings.HasSuffix(reply.GetMessageName(), "_reply") {
		if f := reflect.Indirect(reflect.ValueOf(reply)).FieldByName("Retval"); f.IsValid() && f.CanInt() {
			return govppapi.RetvalToVPPApiError(int32(f.Int()))
		}
	}
	return nil
}
