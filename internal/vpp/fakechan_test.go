package vpp

import (
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
	if r.fn == nil {
		return nil // zero-value reply (retval 0)
	}
	return r.fn(reply)
}
