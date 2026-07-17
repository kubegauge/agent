// push_test.go — the resilience contract against an httptest server: gzip+auth on the wire,
// retry on 5xx, 401 quiet period (no crash-loop), 429 Retry-After, poll-triggered scans,
// opportunistic resend, key file trimming.
package push

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	r := New(url, writeKeyFile(t, "kga_testkey\n"), "test", time.Hour, time.Second,
		func(context.Context) (*wire.AgentReport, error) { return testReport(), nil })
	r.sleep = func(time.Duration) {}
	return r
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
