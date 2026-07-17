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
			t.Errorf("TopCVEs[%d].ID = %s, want %s (ordem: severidade, depois id)", i, res.TopCVEs[i].ID, want)
		}
	}
	if res.TopCVEs[0].Severity != "critical" || res.TopCVEs[0].FixedVersion != "3.0.13-1" {
		t.Errorf("TopCVEs[0] = %+v, want severity critical / fixedVersion 3.0.13-1", res.TopCVEs[0])
	}
	if res.TopCVEs[3].FixedVersion != "" {
		t.Errorf("CVE sem FixedVersion deve ficar vazia, got %q", res.TopCVEs[3].FixedVersion)
	}
	if res.ScanError != "" {
		t.Errorf("ScanError = %q, want vazio", res.ScanError)
	}
}

func TestParseTrivyJSONInvalid(t *testing.T) {
	if _, err := parseTrivyJSON([]byte("not json")); err == nil {
		t.Error("esperava erro para JSON inválido")
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
			t.Error("runner deve receber um context com deadline (timeout por imagem)")
		}
		*calls = append(*calls, args[len(args)-1]) // último arg = ref da imagem
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
		t.Errorf("calls = %v, want exatamente [nginx:1.25] (dedupe + kube-system excluído)", calls)
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
		t.Errorf("imagem ok deve ter sido escaneada normalmente, got %+v", vulns.ByRef["nginx:1.25"])
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("só o sucesso entra no cache: esperava 1 arquivo, got %d", len(entries))
	}
}

func TestScanSnapshotUsesCacheOnSecondPass(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	s := testScanner(fixtureRunner(t, &calls), dir)
	snap := &snapshot.Snapshot{Deployments: []appsv1.Deployment{deployWithImage("default", "web", "nginx:1.25")}}

	first := s.ScanSnapshot(context.Background(), snap)

	failing := func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		t.Error("segundo pass deveria vir 100% do cache")
		return nil, errors.New("não deveria executar")
	}
	s2 := testScanner(failing, dir)
	second := s2.ScanSnapshot(context.Background(), snap)

	if !reflect.DeepEqual(first.ByRef, second.ByRef) {
		t.Errorf("cache deve reproduzir o resultado: first %+v != second %+v", first.ByRef, second.ByRef)
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
		t.Errorf("esperava arquivo de cache sob a chave do digest: %v", err)
	}
}

func TestNewScannerNilWhenBinaryMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if s := NewScanner(""); s != nil {
		t.Error("sem trivy no PATH, NewScanner deve retornar nil")
	}
}
