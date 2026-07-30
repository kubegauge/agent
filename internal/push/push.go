// Package push implements the agent's outbound loop: scan → gzip POST /v1/ingest, plus the ~30s
// GET /v1/agent/commands poll (heartbeat + on-demand scans). Every request carries the cluster API
// key, so the ingest URL must be https unless the operator explicitly opts into cleartext for a
// local endpoint (Config.AllowInsecureHTTP). Resilience contract (spec §2):
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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubegauge/agent/internal/wire"
)

const (
	authBackoff   = 15 * time.Minute
	maxAttempts   = 5
	baseBackoff   = time.Second
	maxBackoff    = time.Minute
	clientTimeout = 90 * time.Second

	// onDemandFactor caps how much faster than its configured interval an on-demand scan may make
	// the agent work. A full scan lists the whole cluster and sweeps every image through trivy, and
	// the command poll runs every 30s — so without a clamp, an ingest endpoint that answers
	// {"scan_requested":true} every time (a compromised or spoofed API, a bug) turns the agent into
	// a permanent load generator against its own API server.
	onDemandFactor = 12
	// minOnDemandInterval floors the clamp: with a 24h plan interval, scanEvery/onDemandFactor
	// alone would make the dashboard's "scan now" button useless for hours.
	minOnDemandInterval = 5 * time.Minute

	// defaultLivenessTimeout is how long the outbound loop may go without completing an iteration
	// before /healthz starts failing and the kubelet restarts the pod. One iteration can
	// legitimately take a long time — a collection pass over a big cluster, a first trivy run that
	// downloads the CVE database, a push with retries — so this is comfortably longer than all of
	// that together, and still shorter than a default scan interval.
	defaultLivenessTimeout = 30 * time.Minute
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
	lastScanAt    time.Time         // start of the most recent scan, for the on-demand clamp

	health *health
}

// health is what /healthz answers from. It is written by the single Run goroutine and read by the
// probe server, hence the mutex.
//
// Liveness means "the outbound loop is still turning", not "the last push succeeded": an
// unreachable API or a revoked key are conditions a restart cannot fix, and the whole design is
// built to sit quietly through them rather than crash-loop. What a restart CAN fix is a wedge — a
// goroutine stuck inside a scan or a push — and that is exactly what a loop iteration failing to
// complete within the limit detects. The last successful scan and push are reported in the body
// for the operator, without gating the verdict.
type health struct {
	mu     sync.Mutex
	limit  time.Duration
	now    func() time.Time
	loopAt time.Time
	scanAt time.Time
	pushAt time.Time
}

func (h *health) mark(field *time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	*field = h.now()
}

// Alive reports whether the outbound loop completed an iteration recently enough, plus a one-line
// summary for the probe body.
func (r *Runner) Alive() (bool, string) {
	h := r.health
	h.mu.Lock()
	defer h.mu.Unlock()

	since := h.now().Sub(h.loopAt)
	summary := fmt.Sprintf("loop %s ago, last scan %s, last delivered report %s (liveness limit %s)",
		since.Round(time.Second), agoOrNever(h.now(), h.scanAt), agoOrNever(h.now(), h.pushAt), h.limit)
	return since < h.limit, summary
}

func agoOrNever(now, at time.Time) string {
	if at.IsZero() {
		return "never"
	}
	return now.Sub(at).Round(time.Second).String() + " ago"
}

// Config is the runner's wiring. AllowInsecureHTTP is the only knob with a security meaning — see
// ValidateIngestURL.
type Config struct {
	IngestURL string
	KeyFile   string
	Version   string
	ScanEvery time.Duration
	PollEvery time.Duration
	// AllowInsecureHTTP permits an http:// ingest URL. Off by default: the cluster API key travels
	// in an Authorization header on every push and every poll, so over plain HTTP it is readable by
	// anything on the path, and a key is enough to impersonate the cluster. The kind dev loop
	// (make agent-dev, pushing to http://host.docker.internal:8080) is the reason the escape hatch
	// exists at all; it must never be the default.
	AllowInsecureHTTP bool
	// LivenessTimeout overrides how long the loop may go without completing an iteration before
	// /healthz fails. Zero means defaultLivenessTimeout; it must stay comfortably above the
	// collection budget, or a slow scan looks like a wedge.
	LivenessTimeout time.Duration
}

// ValidateIngestURL rejects an ingest URL the agent must not send its API key to. Called by New so
// a misconfiguration fails at startup with an explanation, instead of leaking the key on the first
// push.
func ValidateIngestURL(raw string, allowInsecureHTTP bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("ingest URL %q is not a URL: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("ingest URL %q has no host — it must be absolute, e.g. https://api.kubegauge.com", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecureHTTP {
			return nil
		}
		return fmt.Errorf("ingest URL %q uses http: the cluster API key would travel in cleartext on every request. Use https, or pass --allow-insecure-http (chart: allowInsecureHttp=true) if this is a local development endpoint", raw)
	default:
		return fmt.Errorf("ingest URL %q must use https (got scheme %q)", raw, u.Scheme)
	}
}

func New(cfg Config, scan ScanFunc) (*Runner, error) {
	if err := ValidateIngestURL(cfg.IngestURL, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	limit := cfg.LivenessTimeout
	if limit <= 0 {
		limit = defaultLivenessTimeout
	}
	return &Runner{
		health:    &health{limit: limit, now: time.Now, loopAt: time.Now()},
		ingestURL: strings.TrimRight(cfg.IngestURL, "/"),
		keyFile:   cfg.KeyFile,
		version:   cfg.Version,
		scanEvery: cfg.ScanEvery,
		pollEvery: cfg.PollEvery,
		scan:      scan,
		client:    &http.Client{Timeout: clientTimeout},
		logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "kubegauge-agent: "+format+"\n", args...)
		},
		sleep: time.Sleep,
		now:   time.Now,
	}, nil
}

// Run blocks until ctx is done: one scan+push at startup, then the two tickers. Every completed
// iteration marks the loop alive — see health.
func (r *Runner) Run(ctx context.Context) {
	r.scanAndPush(ctx)
	r.health.mark(&r.health.loopAt)
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
		r.health.mark(&r.health.loopAt)
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
	start := r.now()
	r.lastScanAt = start
	r.logf("scanning cluster")
	rpt, err := r.scan(ctx)
	if err != nil {
		r.logf("scan failed: %v (will retry on next tick)", err)
		return
	}
	r.pending = rpt
	r.health.mark(&r.health.scanAt)
	r.logf("scan complete in %s (%d checks)", r.now().Sub(start).Round(time.Second), len(rpt.Checks))
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
			r.logf("report delivered")
			r.pending = nil
			r.health.mark(&r.health.pushAt)
			return
		case isAuthFailure(status):
			r.quietUntil = r.now().Add(authBackoff)
			r.logf("push rejected (%d — key revoked, unknown or not allowed here); quiet for %s, no crash-loop", status, authBackoff)
			return
		case status == http.StatusRequestEntityTooLarge:
			// Retrying cannot help: the same bytes will be too large next time. Drop the report so
			// the next scan starts clean instead of hammering the API with a doomed payload.
			r.pending = nil
			r.logf("push rejected (413 — report too large for the API); dropped, the next scan produces a fresh one")
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
	switch {
	case resp.StatusCode == http.StatusNoContent:
		r.PushPending(ctx)
	case isAuthFailure(resp.StatusCode):
		r.quietUntil = r.now().Add(authBackoff)
		r.logf("poll rejected (%d); quiet for %s", resp.StatusCode, authBackoff)
	case resp.StatusCode == http.StatusOK:
		var cmd struct {
			ScanRequested bool `json:"scan_requested"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&cmd); err == nil && cmd.ScanRequested {
			// The payload is a bool: there is no command to interpret, only a rate to bound.
			if floor := r.onDemandFloor(); r.now().Sub(r.lastScanAt) < floor {
				r.logf("scan requested by the API, refused: last scan was %s ago and on-demand scans are limited to one per %s; delivering the report already in memory instead",
					r.now().Sub(r.lastScanAt).Round(time.Second), floor)
				r.PushPending(ctx)
				return
			}
			r.logf("scan requested by the API — scanning now")
			r.pushNotBefore = time.Time{} // the request opens the window; don't hold the push back
			r.scanAndPush(ctx)
		}
	default:
		r.logf("poll: unexpected status %d", resp.StatusCode)
	}
}

// isAuthFailure covers both ways the API can say "this key is not getting in": 401 for unknown or
// revoked, 403 for known but not allowed here. They are the same situation for the agent — nothing
// it can retry its way out of — so 403 gets 401's quiet window instead of falling through to the
// generic retry path, where a revoked key produced a noisy loop forever.
func isAuthFailure(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// onDemandFloor is the minimum spacing between API-requested scans: fast enough that a human
// pressing "scan now" gets an answer, slow enough that an endpoint answering scan_requested on
// every 30s poll cannot make the agent scan continuously.
func (r *Runner) onDemandFloor() time.Duration {
	floor := r.scanEvery / onDemandFactor
	if floor < minOnDemandInterval {
		floor = minOnDemandInterval
	}
	if floor > r.scanEvery {
		// A deliberately fast scanEvery (dev, or a demo cluster) is its own floor: on-demand scans
		// must never be slower than the timer that already runs.
		floor = r.scanEvery
	}
	return floor
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
