// Package push implements the agent's outbound loop: scan → gzip POST /v1/ingest, plus the ~30s
// GET /v1/agent/commands poll (heartbeat + on-demand scans). Resilience contract (spec §2):
// exponential backoff with jitter on push failures, 15 min quiet period on 401 (revoked key)
// without ever crash-looping, Retry-After honored on 429, freshest report kept in memory for
// resend. A failed push never terminates the process — the pod stays Ready and the dashboard
// surfaces the condition as a missing heartbeat.
package push

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kubegauge/agent/internal/wire"
)

const (
	authBackoff   = 15 * time.Minute
	maxAttempts   = 5
	baseBackoff   = time.Second
	maxBackoff    = time.Minute
	clientTimeout = 90 * time.Second
)

// ScanFunc produces a fresh AgentReport (snapshot + checks + trivy) — injected so tests never
// need a cluster.
type ScanFunc func(context.Context) (*wire.AgentReport, error)

type Runner struct {
	ingestURL string
	keyFile   string
	version   string
	scanEvery time.Duration
	pollEvery time.Duration
	scan      ScanFunc
	client    *http.Client
	logf      func(format string, args ...any)
	sleep     func(time.Duration)
	now       func() time.Time

	pending       *wire.AgentReport // freshest unsent report
	quietUntil    time.Time         // 401 backoff window
	pushNotBefore time.Time         // 429 Retry-After window
}

func New(ingestURL, keyFile, version string, scanEvery, pollEvery time.Duration, scan ScanFunc) *Runner {
	return &Runner{
		ingestURL: strings.TrimRight(ingestURL, "/"),
		keyFile:   keyFile,
		version:   version,
		scanEvery: scanEvery,
		pollEvery: pollEvery,
		scan:      scan,
		client:    &http.Client{Timeout: clientTimeout},
		logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "kubegauge-agent: "+format+"\n", args...)
		},
		sleep: time.Sleep,
		now:   time.Now,
	}
}

// Run blocks until ctx is done: one scan+push at startup, then the two tickers.
func (r *Runner) Run(ctx context.Context) {
	r.scanAndPush(ctx)
	scanTick := time.NewTicker(r.scanEvery)
	pollTick := time.NewTicker(r.pollEvery)
	defer scanTick.Stop()
	defer pollTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTick.C:
			r.scanAndPush(ctx)
		case <-pollTick.C:
			r.Poll(ctx)
		}
	}
}

// key re-reads the API key file on every request, so a rotated Secret takes effect without a
// restart (the kubelet refreshes the mounted file).
func (r *Runner) key() (string, error) {
	raw, err := os.ReadFile(r.keyFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (r *Runner) scanAndPush(ctx context.Context) {
	rpt, err := r.scan(ctx)
	if err != nil {
		r.logf("scan failed: %v (will retry on next tick)", err)
		return
	}
	r.pending = rpt
	r.PushPending(ctx)
}

// PushPending attempts to deliver the freshest report, honoring the 401/429 quiet windows.
func (r *Runner) PushPending(ctx context.Context) {
	if r.pending == nil {
		return
	}
	if now := r.now(); now.Before(r.quietUntil) || now.Before(r.pushNotBefore) {
		return
	}
	body, err := gzipJSON(r.pending)
	if err != nil {
		r.logf("encoding report: %v", err)
		return
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		status, retryAfter, err := r.postOnce(ctx, body)
		switch {
		case err == nil && (status == http.StatusAccepted || status == http.StatusOK):
			r.pending = nil
			return
		case status == http.StatusUnauthorized:
			r.quietUntil = r.now().Add(authBackoff)
			r.logf("push rejected (401 — key revoked or unknown); quiet for %s, no crash-loop", authBackoff)
			return
		case status == http.StatusTooManyRequests:
			r.pushNotBefore = r.now().Add(retryAfter)
			r.logf("push throttled (429); next push not before %s", r.pushNotBefore.Format(time.RFC3339))
			return
		case status == http.StatusPaymentRequired:
			r.pushNotBefore = r.now().Add(authBackoff)
			r.logf("push refused (402 — cluster paused by plan); retrying after %s", authBackoff)
			return
		default:
			r.logf("push attempt %d/%d failed (status %d, err %v)", attempt, maxAttempts, status, err)
			if attempt < maxAttempts {
				r.sleep(backoff(attempt))
			}
		}
	}
	r.logf("push gave up after %d attempts; report kept in memory for resend", maxAttempts)
}

func (r *Runner) postOnce(ctx context.Context, gzBody []byte) (status int, retryAfter time.Duration, err error) {
	key, err := r.key()
	if err != nil {
		return 0, 0, fmt.Errorf("reading api key: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.ingestURL+"/v1/ingest", bytes.NewReader(gzBody))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "kubegauge-agent/"+r.version)
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

// Poll asks the API for pending commands. scan_requested triggers an immediate scan+push; an idle
// 204 opportunistically retries any pending (previously failed) report.
func (r *Runner) Poll(ctx context.Context) {
	if r.now().Before(r.quietUntil) {
		return
	}
	key, err := r.key()
	if err != nil {
		r.logf("reading api key: %v", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.ingestURL+"/v1/agent/commands", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "kubegauge-agent/"+r.version)
	resp, err := r.client.Do(req)
	if err != nil {
		r.logf("poll failed: %v", err)
		return
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		r.PushPending(ctx)
	case http.StatusUnauthorized:
		r.quietUntil = r.now().Add(authBackoff)
		r.logf("poll rejected (401); quiet for %s", authBackoff)
	case http.StatusOK:
		var cmd struct {
			ScanRequested bool `json:"scan_requested"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&cmd); err == nil && cmd.ScanRequested {
			r.logf("scan requested by the API — scanning now")
			r.pushNotBefore = time.Time{} // the request opens the window; don't hold the push back
			r.scanAndPush(ctx)
		}
	default:
		r.logf("poll: unexpected status %d", resp.StatusCode)
	}
}

func gzipJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// backoff: exponential 1s,2s,4s,... capped at 1 min, ±20% jitter.
func backoff(attempt int) time.Duration {
	d := baseBackoff << (attempt - 1)
	if d > maxBackoff {
		d = maxBackoff
	}
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return time.Minute
	}
	return time.Duration(secs) * time.Second
}
