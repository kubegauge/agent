// Package main implements kubegauge-agent: a push-only outbound agent — scan on a timer, POST the
// AgentReport to the KubeGauge API, poll for on-demand scan commands. The only inbound surface is
// GET /healthz for probes; nothing else ever listens (Fase 4 M1).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubegauge/agent/internal/checks"
	"github.com/kubegauge/agent/internal/kube"
	"github.com/kubegauge/agent/internal/push"
	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
	"github.com/kubegauge/agent/internal/trivy"
	"github.com/kubegauge/agent/internal/wire"
)

// version is stamped via -ldflags at build time (CI passes the git tag).
var version = "dev"

func main() {
	fs := flag.NewFlagSet("kubegauge-agent", flag.ExitOnError)
	clusterName := fs.String("cluster-name", "", "cluster name shown in the dashboard (required)")
	ingestURL := fs.String("ingest-url", "", "base URL of the KubeGauge API (required), e.g. https://api.kubegauge.com")
	apiKeyFile := fs.String("api-key-file", "", "path to the file holding the cluster API key (required; the chart mounts it from a Secret)")
	scanInterval := fs.Duration("scan-interval", time.Hour, "interval between full scans pushed to the API")
	pollInterval := fs.Duration("poll-interval", 30*time.Second, "interval between command polls (doubles as heartbeat)")
	healthzAddr := fs.String("healthz-addr", "0.0.0.0:8787", "bind address of the probe-only healthz endpoint")
	noTrivy := fs.Bool("no-trivy", false, "disable image vulnerability scanning (KG-SU-003 reports info)")
	trivyCacheDir := fs.String("trivy-cache-dir", "", "trivy result cache directory (empty disables caching)")
	collectTimeout := fs.Duration("collect-timeout", snapshot.DefaultCollectTimeout, "budget for one collection pass over the API server (raise it on very large clusters)")
	_ = fs.Parse(os.Args[1:])

	if *clusterName == "" || *ingestURL == "" || *apiKeyFile == "" {
		fmt.Fprintln(os.Stderr, "error: --cluster-name, --ingest-url and --api-key-file are required")
		fs.Usage()
		os.Exit(1)
	}

	cs, err := kube.InClusterClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var scanner *trivy.Scanner
	if !*noTrivy {
		if scanner = trivy.NewScanner(*trivyCacheDir); scanner == nil {
			fmt.Fprintln(os.Stderr, "kubegauge-agent: trivy binary not found in PATH — KG-SU-003 will report info")
		}
	}

	// Probe-only HTTP surface: liveness/readiness. Deliberately NOT the old scan API — nothing
	// consumes the agent over the network anymore.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		if err := http.ListenAndServe(*healthzAddr, mux); err != nil {
			fmt.Fprintln(os.Stderr, "kubegauge-agent: healthz:", err)
			os.Exit(1)
		}
	}()

	firstTrivy := true
	scan := func(ctx context.Context) (*wire.AgentReport, error) {
		snap, err := snapshot.TakeWithOptions(ctx, cs, snapshot.Options{Timeout: *collectTimeout})
		if err != nil {
			return nil, err
		}
		// A partial pass still reports; it must never look complete. The dependent checks come out
		// as "na" (never a fake "pass"), and the reason lands here for the operator.
		for _, ce := range snap.Uncollected {
			fmt.Fprintf(os.Stderr, "kubegauge-agent: could not collect %s (%s) — checks that need it report N/A\n", ce.Resource, ce.Reason)
		}
		if scanner != nil {
			if firstTrivy {
				fmt.Fprintln(os.Stderr, "kubegauge-agent: first image scan may download the trivy CVE database (can take a few minutes)")
				firstTrivy = false
			}
			snap.ImageVulns = scanner.ScanSnapshot(ctx, snap)
		}
		rpt := wire.Build(snap, *clusterName, version, time.Now(), checks.Run(snap), checks.RbacFindings(snap))
		if len(rpt.Network.Flows) >= report.MaxFlows {
			fmt.Fprintf(os.Stderr, "kubegauge-agent: network graph truncated at %d flows — it is a sample of this cluster's candidates, in priority order (internet exposure first)\n", report.MaxFlows)
		}
		return rpt, nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "kubegauge-agent %s: cluster %q → %s (scan %s, poll %s)\n",
		version, *clusterName, *ingestURL, scanInterval.String(), pollInterval.String())
	push.New(*ingestURL, *apiKeyFile, version, *scanInterval, *pollInterval, scan).Run(ctx)
}
