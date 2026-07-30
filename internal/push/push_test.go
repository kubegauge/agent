// push_test.go — the resilience contract against an httptest server: gzip+auth on the wire,
// retry on 5xx, 401 quiet period (no crash-loop), 429 Retry-After, poll-triggered scans,
// opportunistic resend, key file trimming.
package push

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubegauge/agent/internal/wire"
)

func testReport() *wire.AgentReport {
	return &wire.AgentReport{SchemaVersion: 1, AgentVersion: "test", ClusterName: "t", TakenAt: "2026-07-17T12:00:00Z"}
}

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api-key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestRunner(t *testing.T, url string) *Runner {
	t.Helper()
	// httptest serves http://127.0.0.1:port, which is exactly the case AllowInsecureHTTP exists for.
	r, err := New(Config{
		IngestURL: url, KeyFile: writeKeyFile(t, "kga_testkey\n"), Version: "test",
		ScanEvery: time.Hour, PollEvery: time.Second, AllowInsecureHTTP: true,
	}, func(context.Context) (*wire.AgentReport, error) { return testReport(), nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.sleep = func(time.Duration) {}
	return r
}

// TestIngestURLMustBeHTTPS: the cluster API key rides in an Authorization header on every request,
// so an http:// endpoint has to be an explicit, deliberate choice — not something a typo in a
// values file can arrange.
func TestIngestURLMustBeHTTPS(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
	}{
		{name: "https is the norm", url: "https://api.kubegauge.com", allowInsecure: false},
		{name: "http is refused by default", url: "http://api.kubegauge.com", allowInsecure: false, wantErr: true},
		{name: "http with the explicit opt-in (the kind dev loop)", url: "http://host.docker.internal:8080", allowInsecure: true},
		{name: "a bare host is not a URL the agent can trust", url: "api.kubegauge.com", allowInsecure: false, wantErr: true},
		{name: "other schemes are refused outright", url: "ftp://api.kubegauge.com", allowInsecure: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIngestURL(tt.url, tt.allowInsecure)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateIngestURL(%q, %v) error = %v, wantErr %v", tt.url, tt.allowInsecure, err, tt.wantErr)
			}
			if _, err := New(Config{IngestURL: tt.url, AllowInsecureHTTP: tt.allowInsecure}, nil); (err != nil) != tt.wantErr {
				t.Errorf("New with %q must refuse the same URLs ValidateIngestURL does (err = %v)", tt.url, err)
			}
		})
	}
}

func TestPushSendsGzipJSONWithAuth(t *testing.T) {
	var gotAuth, gotEncoding, gotCluster string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ingest" || r.Method != "POST" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotEncoding = r.Header.Get("Content-Encoding")
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body is not gzip: %v", err)
		} else {
			var rpt wire.AgentReport
			raw, _ := io.ReadAll(zr)
			_ = json.Unmarshal(raw, &rpt)
			gotCluster = rpt.ClusterName
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.scanAndPush(context.Background())

	if gotAuth != "Bearer kga_testkey" {
		t.Fatalf("Authorization = %q (key file must be trimmed)", gotAuth)
	}
	if gotEncoding != "gzip" || gotCluster != "t" {
		t.Fatalf("wire shape wrong: encoding=%q cluster=%q", gotEncoding, gotCluster)
	}
	if r.pending != nil {
		t.Fatal("successful push must clear pending")
	}
}

func TestPushRetriesOn5xxThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.scanAndPush(context.Background())

	if calls.Load() != 3 {
		t.Fatalf("push tried %d times, want 3 (2 failures + success)", calls.Load())
	}
	if r.pending != nil {
		t.Fatal("pending must clear after eventual success")
	}
}

func TestPush401EntersQuietPeriodWithoutCrash(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.scanAndPush(context.Background())

	if calls.Load() != 1 {
		t.Fatalf("401 must not retry (got %d calls)", calls.Load())
	}
	if r.pending == nil {
		t.Fatal("report must be kept for resend after 401")
	}
	if !r.quietUntil.After(r.now()) {
		t.Fatal("401 must open a quiet window")
	}
	r.PushPending(context.Background()) // inside the quiet window: no new request
	if calls.Load() != 1 {
		t.Fatalf("push during quiet window made a request (%d calls)", calls.Load())
	}
}

// TestPush403IsQuietLikeA401: a key that is known but no longer allowed used to fall through to
// the generic retry path — five attempts with backoff, every scan interval, forever, with a log
// line each time. There is nothing to retry.
func TestPush403IsQuietLikeA401(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.scanAndPush(context.Background())

	if calls.Load() != 1 {
		t.Fatalf("403 must not retry (got %d calls)", calls.Load())
	}
	if r.pending == nil {
		t.Error("the report must be kept for resend once access is restored")
	}
	if !r.quietUntil.After(r.now()) {
		t.Error("403 must open a quiet window")
	}

	r.Poll(context.Background()) // inside the quiet window: no new request
	if calls.Load() != 1 {
		t.Fatalf("polling during the 403 quiet window made a request (%d calls)", calls.Load())
	}
}

// TestPush413DropsTheReport: the same bytes will be too large on every retry, so the only useful
// answer is to stop carrying them.
func TestPush413DropsTheReport(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.scanAndPush(context.Background())

	if calls.Load() != 1 {
		t.Fatalf("413 must not retry (got %d calls)", calls.Load())
	}
	if r.pending != nil {
		t.Error("a report the API will never accept must not be kept for resend")
	}
}

func TestPush429HonorsRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	before := time.Now()
	r.scanAndPush(context.Background())

	min := before.Add(110 * time.Second)
	if r.pushNotBefore.Before(min) {
		t.Fatalf("pushNotBefore = %s, want ≥ %s (Retry-After 120s)", r.pushNotBefore, min)
	}
	if r.pending == nil {
		t.Fatal("throttled report must be kept for resend")
	}
}

func TestPollTriggersImmediateScanAndPush(t *testing.T) {
	var ingests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent/commands", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"scan_requested": true}`))
	})
	mux.HandleFunc("POST /v1/ingest", func(w http.ResponseWriter, _ *http.Request) {
		ingests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.Poll(context.Background())

	if ingests.Load() != 1 {
		t.Fatalf("scan_requested must cause an immediate push (got %d)", ingests.Load())
	}
}

// TestPollRefusesScanFloodButStillDelivers: an ingest endpoint that answers scan_requested on every
// 30s poll must not be able to make the agent list the whole cluster and sweep every image through
// trivy forever. The refused request still gets the freshest report the agent already has.
func TestPollRefusesScanFloodButStillDelivers(t *testing.T) {
	var scans, ingests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent/commands", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"scan_requested": true}`))
	})
	mux.HandleFunc("POST /v1/ingest", func(w http.ResponseWriter, _ *http.Request) {
		ingests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.scan = func(context.Context) (*wire.AgentReport, error) {
		scans.Add(1)
		return testReport(), nil
	}
	var logs []string
	r.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }

	for i := 0; i < 10; i++ {
		r.Poll(context.Background())
	}

	if scans.Load() != 1 {
		t.Errorf("10 scan requests in a row produced %d scans, want 1 (the rest clamped)", scans.Load())
	}
	if ingests.Load() != 1 {
		t.Errorf("only the accepted scan should have pushed (%d ingests)", ingests.Load())
	}
	if !strings.Contains(strings.Join(logs, "\n"), "refused") {
		t.Errorf("a refused on-demand scan must say so; logs:\n%s", strings.Join(logs, "\n"))
	}

	// A refusal is not a dead end: whatever the agent already holds still goes out.
	r.pending = testReport()
	r.Poll(context.Background())
	if scans.Load() != 1 {
		t.Errorf("the clamp leaked: %d scans", scans.Load())
	}
	if ingests.Load() != 2 {
		t.Errorf("a refused request must still deliver the pending report (%d ingests)", ingests.Load())
	}
}

// TestOnDemandFloor pins the clamp: a small factor of the configured interval, floored so the
// dashboard button still works on a 24h plan, and never slower than the timer itself.
func TestOnDemandFloor(t *testing.T) {
	tests := []struct {
		scanEvery time.Duration
		want      time.Duration
	}{
		{scanEvery: time.Hour, want: 5 * time.Minute},
		{scanEvery: 24 * time.Hour, want: 2 * time.Hour},
		{scanEvery: time.Minute, want: time.Minute},
	}
	for _, tt := range tests {
		r := &Runner{scanEvery: tt.scanEvery}
		if got := r.onDemandFloor(); got != tt.want {
			t.Errorf("scanEvery %s: floor = %s, want %s", tt.scanEvery, got, tt.want)
		}
	}
}

func TestPollIdleDeliversPendingReport(t *testing.T) {
	var ingests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/agent/commands", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/ingest", func(w http.ResponseWriter, _ *http.Request) {
		ingests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	r.pending = testReport() // leftover from a failed push
	r.Poll(context.Background())

	if ingests.Load() != 1 || r.pending != nil {
		t.Fatalf("idle poll must deliver the pending report (ingests=%d pending=%v)", ingests.Load(), r.pending != nil)
	}
}

// TestScanAndPushLogsProgress: a healthy scan+push emits a start, a scan-complete (with timing so
// the trivy DB-download latency is visible) and a delivery line — so an operator can tell "working"
// from "hung" without opening the dashboard.
func TestScanAndPushLogsProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	r := newTestRunner(t, srv.URL)
	var logs []string
	r.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	r.scanAndPush(context.Background())

	joined := strings.Join(logs, "\n")
	for _, want := range []string{"scanning cluster", "scan complete", "report delivered"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in progress logs; got:\n%s", want, joined)
		}
	}
}
