package vpp

import (
	"fmt"

	govppapi "go.fd.io/govpp/api"
)

// exec sends one request and receives its reply, wrapping any failure as
// "vpp: <op>: <err>". govpp's ReceiveReply ALREADY converts a non-zero Retval on
// any *_reply message into api.VPPApiError (core/channel.go reflects the Retval
// field unconditionally), so a VPP-level rejection surfaces through err here with
// a NAMED error (e.g. "VPPApiError: Invalid value (-7)") — callers must NOT
// re-check reply.Retval afterwards: such checks are unreachable, and ~15 copies
// of that dead pattern had accumulated across this package before exec.
func exec(ch govppapi.Channel, op string, req, reply govppapi.Message) error {
	if err := ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: %s: %w", op, err)
	}
	return nil
}

// dumpAll drives a multi-part dump: it sends req and calls each() for every
// streamed details message until the stop sentinel. P is the generated details
// pointer type; a fresh T is allocated per iteration (ReceiveReply decodes into
// it, so entries must not alias).
func dumpAll[T any, P interface {
	*T
	govppapi.Message
}](ch govppapi.Channel, op string, req govppapi.Message, each func(P)) error {
	reqCtx := ch.SendMultiRequest(req)
	for {
		d := P(new(T))
		stop, err := reqCtx.ReceiveReply(d)
		if err != nil {
			return fmt.Errorf("vpp: %s: %w", op, err)
		}
		if stop {
			return nil
		}
		each(d)
	}
}
