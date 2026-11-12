// Command fakeserver is a DEVELOPMENT-ONLY stand-in for the DranzoRMM agent
// gateway. It wraps internal/testserver: a throwaway CA and command key that
// live in memory, enrollment with a generated token, and the WebSocket endpoint.
//
// It exists so the agent can be run locally ("dranzo-agent run --foreground")
// and its footprint measured without the real server. Never deploy it.
//
//	fakeserver --listen 127.0.0.1:8443 --out ./dev-data
//
// writes ca.pem, trust.json and bootstrap.json into --out; then:
//
//	dranzo-agent run --foreground --data-dir ./dev-data
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dranzo/dranzormm/agent/internal/config"
	"github.com/dranzo/dranzormm/agent/internal/protocol"
	"github.com/dranzo/dranzormm/agent/internal/testserver"
	"github.com/dranzo/dranzormm/agent/internal/trust"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fakeserver:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:8443", "address to listen on")
	out := flag.String("out", "", "agent data directory to prepare (ca.pem, trust.json, bootstrap.json)")
	heartbeat := flag.Int("heartbeat", 60, "heartbeatSeconds announced in hello.ack")
	demo := flag.Bool("demo-job", false, "dispatch one signed 'inventory.refresh' job to every device that connects")
	uninstallAfter := flag.Duration("demo-uninstall-after", 0, "dispatch a signed 'agent.uninstall' job to every device this long after it connected (0 = never)")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv, err := testserver.New(testserver.Options{Listener: ln, HeartbeatSeconds: *heartbeat})
	if err != nil {
		return err
	}
	defer srv.Close()
	fmt.Printf("DEVELOPMENT fake server listening on %s\n", srv.URL)

	if *out != "" {
		paths := config.ResolvePaths(*out)
		if err := paths.Ensure(); err != nil {
			return err
		}
		if err := trust.Install(paths.CAFile(), paths.TrustFile(), srv.CAPEM, srv.TrustKeys()); err != nil {
			return err
		}
		if err := config.SaveBootstrap(paths, &config.Bootstrap{ServerURL: srv.URL, Token: srv.Token}); err != nil {
			return err
		}
		fmt.Printf("prepared agent data directory %s\nrun: dranzo-agent run --foreground --data-dir %s\n", paths.StateDir, filepath.Clean(*out))
	} else {
		fmt.Println("no --out given: pass the CA and trust file to the agent yourself")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	seen := map[string]int{}
	dispatched := map[string]bool{}
	firstSeen := map[string]time.Time{}
	uninstalled := map[string]bool{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		for _, id := range srv.Devices() {
			msgs := srv.Messages(id, seen[id])
			for _, m := range msgs {
				fmt.Printf("%s  %s  <- %-18s %d bytes\n", time.Now().Format("15:04:05"), id[:8], m.Type, len(m.Payload))
			}
			seen[id] += len(msgs)
			if _, ok := firstSeen[id]; !ok && srv.Hello(id) != nil {
				firstSeen[id] = time.Now()
			}
			if at, ok := firstSeen[id]; ok && *uninstallAfter > 0 && !uninstalled[id] && time.Since(at) >= *uninstallAfter {
				uninstalled[id] = true
				d := protocol.JobDispatch{
					SignedCommon: testserver.Common(id), JobRunID: protocol.NewID(),
					Kind: protocol.KindAgentUninstall, TimeoutSeconds: 60, Spec: json.RawMessage(`{}`),
				}
				if _, err := srv.SendSigned(id, protocol.TypeJobDispatch, d); err == nil {
					fmt.Printf("%s  %s  -> job.dispatch agent.uninstall\n", time.Now().Format("15:04:05"), id[:8])
				}
			}
			if *demo && !dispatched[id] && srv.Hello(id) != nil {
				dispatched[id] = true
				d := protocol.JobDispatch{
					SignedCommon: testserver.Common(id), JobRunID: protocol.NewID(),
					Kind: protocol.KindInventoryRefresh, TimeoutSeconds: 60, Spec: json.RawMessage(`{}`),
				}
				if _, err := srv.SendSigned(id, protocol.TypeJobDispatch, d); err == nil {
					fmt.Printf("%s  %s  -> job.dispatch inventory.refresh\n", time.Now().Format("15:04:05"), id[:8])
				}
			}
		}
	}
}
