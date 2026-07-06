// minirepro: faithful repro of the agent's shared-connection usage — concurrent
// forwarding-probe cli_inband ping + reconcile-style policer_dump on ONE vpp.Conn
// (exact agent code paths). Isolates whether the concurrent cli_inband ping wedges
// policer_dump. Build static, run in the vpp container.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fivetime/sbw-limiter/internal/vpp"
)

func main() {
	sock := "/run/vpp/api.sock"
	if len(os.Args) > 1 {
		sock = os.Args[1]
	}
	ctx := context.Background()
	conn, err := vpp.Dial(ctx, sock, vpp.WithReplyTimeout(5*time.Second), vpp.WithHealthCheck(30*time.Second))
	if err != nil {
		fmt.Println("dial err:", err)
		os.Exit(1)
	}
	fmt.Println("connected (agent-style). starting concurrent forwarding-probe ping + policer_dump loop...")

	// forwarding probe: cli_inband ping every 2s on the shared connection (like the agent)
	go func() {
		for {
			_, _, err := conn.Ping("fc00:4:2:3::68", 3, 0.1, 2*time.Second)
			if err != nil {
				fmt.Println("  [probe] ping err:", err)
			}
			time.Sleep(2 * time.Second)
		}
	}()

	// reconcile-style policer_dump every 2s (fresh channel each pass, exact agent path)
	for i := 0; i < 60; i++ {
		ch, err := conn.Channel()
		if err != nil {
			fmt.Printf("[%d] channel err: %v\n", i, err)
			time.Sleep(2 * time.Second)
			continue
		}
		t0 := time.Now()
		_, err = vpp.NewPolicers(ch).Dump()
		ch.Close()
		if err != nil {
			fmt.Printf("[%d] POLICER_DUMP FAIL after %v: %v\n", i, time.Since(t0), err)
		} else {
			fmt.Printf("[%d] policer_dump OK in %v\n", i, time.Since(t0))
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Println("done")
}
