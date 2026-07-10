package vpp

import (
	"fmt"
	"strings"
	"time"

	"go.fd.io/govpp/binapi/vlib"
)

// CliInband runs a VPP debug-CLI command over the binary API (cli_inband) and returns
// its text output. VPP's data-plane `ping` has no dedicated binary API, so the §4.2.7
// forwarding probe drives it through here. The cli_inband message is CRC-stable
// (0xf8377302, matches the lab image), so the govpp prebuilt binapi is safe to use.
// timeout bounds a wedged main thread (a stuck ControlPing would otherwise hang).
func (c *Conn) CliInband(cmd string, timeout time.Duration) (string, error) {
	ch, err := c.Channel()
	if err != nil {
		return "", err
	}
	defer ch.Close()
	if timeout > 0 {
		ch.SetReplyTimeout(timeout)
	}
	reply := &vlib.CliInbandReply{}
	if err := exec(ch, fmt.Sprintf("cli_inband %q", cmd), &vlib.CliInband{Cmd: cmd}, reply); err != nil {
		return "", err
	}
	return reply.Reply, nil
}

// Ping runs VPP's data-plane ICMP ping to target (count echoes at the given interval in
// seconds) via cli_inband and returns how many were sent and received. A
// forwarding-healthy path returns recv > 0; recv == 0 is a black-hole for that path.
func (c *Conn) Ping(target string, count int, intervalSec float64, timeout time.Duration) (sent, recv int, err error) {
	out, err := c.CliInband(fmt.Sprintf("ping %s repeat %d interval %.2f", target, count, intervalSec), timeout)
	if err != nil {
		return 0, 0, err
	}
	sent, recv, ok := parsePingStats(out)
	if !ok {
		return 0, 0, fmt.Errorf("vpp: ping %s: unparseable output %q", target, out)
	}
	return sent, recv, nil
}

// parsePingStats reads VPP's ping summary line, e.g.
//
//	"Statistics: 3 sent, 3 received, 0% packet loss"
//
// returning sent/received and ok=false if no such line is present.
func parsePingStats(out string) (sent, recv int, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Statistics:") {
			continue
		}
		if n, _ := fmt.Sscanf(line, "Statistics: %d sent, %d received", &sent, &recv); n == 2 {
			return sent, recv, true
		}
	}
	return 0, 0, false
}
