package bird

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Configure reply codes (BIRD v3.3.1 sysdep/unix/main.c cli_msg calls).
const (
	CodeReconfigured       = 3  // "Reconfigured"
	CodeReconfigInProgress = 4  // "Reconfiguration in progress"
	CodeReconfigQueued     = 5  // "Reconfiguration already in progress, queueing"
	CodeReconfigConfirmed  = 18 // "Reconfiguration confirmed"
	CodeNothingToDo        = 19 // "Nothing to do"
	CodeConfigOK           = 20 // "Configuration OK" (configure check)
)

// ConfigureResult is the outcome of a configure-family command. BIRD errors
// (8xxx/9xxx) surface as *CommandError from the method instead.
type ConfigureResult struct {
	Code    int
	Message string
}

// Accepted reports whether the new configuration was applied or is being
// applied (done / in progress / queued).
func (r ConfigureResult) Accepted() bool {
	return r.Code == CodeReconfigured || r.Code == CodeReconfigInProgress || r.Code == CodeReconfigQueued
}

func (c *Client) configure(cmd string) (ConfigureResult, error) {
	reply, err := c.Do(cmd)
	if err != nil {
		return ConfigureResult{}, err
	}
	return ConfigureResult{Code: reply.Code, Message: reply.Text()}, nil
}

// Configure reloads the default configuration file ("configure").
func (c *Client) Configure() (ConfigureResult, error) {
	return c.configure("configure")
}

// ConfigureSoft reloads ignoring filter changes ("configure soft").
func (c *Client) ConfigureSoft() (ConfigureResult, error) {
	return c.configure("configure soft")
}

// ConfigureTimeout reloads with an automatic undo window ("configure timeout
// N"): unless confirmed within seconds, BIRD rolls back (§7 safe reload).
func (c *Client) ConfigureTimeout(seconds int) (ConfigureResult, error) {
	return c.configure(fmt.Sprintf("configure timeout %d", seconds))
}

// ConfigureConfirm confirms a pending timed reconfiguration.
func (c *Client) ConfigureConfirm() (ConfigureResult, error) {
	return c.configure("configure confirm")
}

// ConfigureUndo rolls back to the previous configuration.
func (c *Client) ConfigureUndo() (ConfigureResult, error) {
	return c.configure("configure undo")
}

// ConfigureCheck parses a configuration without applying it. With path == ""
// the default config file is checked; success is CodeConfigOK.
func (c *Client) ConfigureCheck(path string) (ConfigureResult, error) {
	cmd := "configure check"
	if path != "" {
		cmd = fmt.Sprintf("configure check %q", path)
	}
	return c.configure(cmd)
}

// TableRouteCount is one table's line from "show route count".
type TableRouteCount struct {
	Table    string
	Routes   uint64 // shown (= total in count mode)
	Networks uint64
}

// RouteCount is the parsed result of "show route count". Totals come from the
// final "Total:" line when present (multi-table), else summed per-table.
type RouteCount struct {
	Tables        []TableRouteCount
	TotalRoutes   uint64
	TotalNetworks uint64
}

var (
	tableCountRe = regexp.MustCompile(`^(\d+) of (\d+) routes for (\d+) networks in table (\S+)`)
	totalCountRe = regexp.MustCompile(`^Total: (\d+) of (\d+) routes for (\d+) networks`)
)

// ShowRouteCount runs "show route count" — one leg of the three-way route
// accounting (DESIGN.md §5.1: BIRD RIB vs Linux RIB vs VPP FIB).
func (c *Client) ShowRouteCount() (RouteCount, error) {
	reply, err := c.Do("show route count")
	if err != nil {
		return RouteCount{}, err
	}
	var rc RouteCount
	sawTotal := false
	for _, l := range reply.Lines {
		if m := tableCountRe.FindStringSubmatch(l.Text); m != nil {
			routes, _ := strconv.ParseUint(m[2], 10, 64)
			nets, _ := strconv.ParseUint(m[3], 10, 64)
			rc.Tables = append(rc.Tables, TableRouteCount{Table: m[4], Routes: routes, Networks: nets})
			continue
		}
		if m := totalCountRe.FindStringSubmatch(l.Text); m != nil {
			rc.TotalRoutes, _ = strconv.ParseUint(m[2], 10, 64)
			rc.TotalNetworks, _ = strconv.ParseUint(m[3], 10, 64)
			sawTotal = true
		}
	}
	if !sawTotal {
		for _, t := range rc.Tables {
			rc.TotalRoutes += t.Routes
			rc.TotalNetworks += t.Networks
		}
	}
	return rc, nil
}

// ShowRouteExported returns the prefixes truly exported to the named protocol
// ("show route exported <proto>", BIRD 3 RSEM_EXPORTED — the real already-
// exported set, not a filter simulation; DESIGN.md §1.1-1). This is the
// anchor-leak check's "must be present" leg (§4.2-3).
func (c *Client) ShowRouteExported(proto string) ([]netip.Prefix, error) {
	reply, err := c.Do("show route exported " + proto)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	for _, l := range reply.Lines {
		// Route lines start with the network at column 0; extra-path /
		// attribute lines are indented and parse fails harmlessly.
		if l.Text == "" || l.Text[0] == ' ' || l.Text[0] == '\t' {
			continue
		}
		first := strings.Fields(l.Text)[0]
		p, err := netip.ParsePrefix(first)
		if err != nil {
			continue
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

// ProtocolStatus is one row of "show protocols".
type ProtocolStatus struct {
	Name  string
	Proto string
	Table string
	State string // up | down | start | stop | flush
	Since string
	Info  string
}

// Up reports whether the protocol is in state "up".
func (p ProtocolStatus) Up() bool { return p.State == "up" }

const (
	codeProtocolRow    = 1002
	codeProtocolHeader = 2002
)

// ShowProtocols runs "show protocols" and parses the table rows. Header
// (2002) and detail (1006, from "all") lines are ignored by code.
func (c *Client) ShowProtocols() ([]ProtocolStatus, error) {
	reply, err := c.Do("show protocols")
	if err != nil {
		return nil, err
	}
	var out []ProtocolStatus
	for _, l := range reply.Lines {
		if l.Code != codeProtocolRow {
			continue
		}
		f := strings.Fields(l.Text)
		if len(f) < 5 {
			continue
		}
		ps := ProtocolStatus{Name: f[0], Proto: f[1], Table: f[2], State: f[3], Since: f[4]}
		if len(f) > 5 {
			ps.Info = strings.Join(f[5:], " ")
		}
		out = append(out, ps)
	}
	return out, nil
}

// Protocol returns the status row for one named protocol, or false if absent.
func (c *Client) Protocol(name string) (ProtocolStatus, bool, error) {
	all, err := c.ShowProtocols()
	if err != nil {
		return ProtocolStatus{}, false, err
	}
	for _, p := range all {
		if p.Name == name {
			return p, true, nil
		}
	}
	return ProtocolStatus{}, false, nil
}
