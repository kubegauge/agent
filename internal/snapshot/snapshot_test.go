// snapshot_test.go verifies Take's security-critical guarantees: the collector never issues a
// single read against Secrets (the ClusterRole does not grant one), and a ConfigMap's values never
// survive past the metadata-only conversion inside Take, no matter how the resulting Snapshot is
// later serialized (JSON, logs, etc.).
package snapshot

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"k8s.io/client-go/kubernetes/fake"
)

// secretValueMarker is a unique, unmistakable string planted as a Secret/ConfigMap VALUE in the
// fixtures below. If it ever appears in a marshaled Snapshot, a value leaked past the metadata-only
// conversion this test exists to guarantee.
const secretValueMarker = "SUPER-SECRET-DO-NOT-LEAK-9f3c2a1b"

// TestTakeCollectsServices covers the M5 addition: Services are listed (get/list only, full
// objects — they carry no sensitive payload) so report.BuildNetwork can derive flow candidates
// from them (PLAN-FASE-2.md §8).
func TestTakeCollectsServices(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "api"},
			Ports:    []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}

	snap, err := Take(context.Background(), fake.NewSimpleClientset(svc))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	if len(snap.Services) != 1 || snap.Services[0].Name != "api" || snap.Services[0].Namespace != "default" {
		t.Fatalf("expected the default/api service in the snapshot, got %+v", snap.Services)
	}
}

// TestSnapshotNeverListsSecrets is the guarantee behind the missing `secrets` entry in the chart's
// ClusterRole: no code path in Take may read a Secret, so the ServiceAccount token cannot be turned
// into a cluster-wide credential oracle. Discarding values in-process (the pre-0.16 behavior) did
// not achieve that — the grant itself had to go.
func TestSnapshotNeverListsSecrets(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "payments"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"password": []byte(secretValueMarker)},
	}
	cs := fake.NewSimpleClientset(secret)

	var secretVerbs []string
	cs.PrependReactor("*", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		secretVerbs = append(secretVerbs, action.GetVerb())
		return false, nil, nil
	})

	snap, err := Take(context.Background(), cs)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if len(secretVerbs) != 0 {
		t.Fatalf("Take issued %v against secrets; the agent must never read them", secretVerbs)
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(raw), secretValueMarker) {
		t.Fatalf("marker value leaked into the serialized Snapshot:\n%s", raw)
	}
}

func TestConfigMapValuesNeverLeaveSnapshot(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "app-config", Namespace: "payments"},
		Data:       map[string]string{"password": secretValueMarker, "log_level": "debug"},
		BinaryData: map[string][]byte{"cert.bin": []byte(secretValueMarker)},
	}

	cs := fake.NewSimpleClientset([]runtime.Object{configMap}...)

	snap, err := Take(context.Background(), cs)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(raw), secretValueMarker) {
		t.Fatalf("marker value leaked into the serialized Snapshot:\n%s", raw)
	}

	if len(snap.ConfigMaps) != 1 {
		t.Fatalf("expected 1 ConfigMapMeta, got %d: %+v", len(snap.ConfigMaps), snap.ConfigMaps)
	}
	gotCM := snap.ConfigMaps[0]
	if gotCM.Name != "app-config" || gotCM.Namespace != "payments" {
		t.Errorf("ConfigMapMeta identity = %+v, want name=app-config namespace=payments", gotCM)
	}
	wantKeys := []string{"cert.bin", "log_level", "password"}
	if !reflect.DeepEqual(gotCM.Keys, wantKeys) {
		t.Errorf("ConfigMapMeta.Keys = %v, want %v (sorted, key names only, no values)", gotCM.Keys, wantKeys)
	}
}

// TestListAllFollowsContinueTokens covers the pagination that replaced 18 unbounded cluster-wide
// List calls: a collection that arrives in pages must come back whole.
func TestListAllFollowsContinueTokens(t *testing.T) {
	pages := [][]string{{"a", "b"}, {"c", "d"}, {"e"}}
	var seen []string
	got, err := listAll(context.Background(), func(_ context.Context, o metav1.ListOptions) ([]string, string, error) {
		if o.Limit != listPageSize {
			t.Errorf("page requested with Limit %d, want %d", o.Limit, listPageSize)
		}
		seen = append(seen, o.Continue)
		i := len(seen) - 1
		next := ""
		if i+1 < len(pages) {
			next = "token-" + pages[i+1][0]
		}
		return pages[i], next, nil
	})
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if want := []string{"a", "b", "c", "d", "e"}; !reflect.DeepEqual(got, want) {
		t.Errorf("items = %v, want %v", got, want)
	}
	if want := []string{"", "token-c", "token-e"}; !reflect.DeepEqual(seen, want) {
		t.Errorf("continue tokens sent = %v, want %v", seen, want)
	}
}

// TestListAllRestartsOnExpiredContinueToken: a pass long enough to outlive the API server's
// snapshot gets 410 Gone halfway through. Restarting beats failing the scan.
func TestListAllRestartsOnExpiredContinueToken(t *testing.T) {
	var calls int
	got, err := listAll(context.Background(), func(_ context.Context, o metav1.ListOptions) ([]string, string, error) {
		calls++
		switch {
		case calls == 1:
			return []string{"a"}, "expiring-token", nil
		case calls == 2:
			return nil, "", apierrors.NewResourceExpired("continue token expired")
		default:
			return []string{"a", "b"}, "", nil
		}
	})
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("items after restart = %v, want %v", got, want)
	}
}

// TestOptionalCollectionFailureDegradesInsteadOfAborting is the "a partial report beats no report"
// contract: an operator who trims `list configmaps` out of the ClusterRole (or a cluster where that
// one list times out) still gets every other check, and the gap is recorded rather than hidden.
func TestOptionalCollectionFailureDegradesInsteadOfAborting(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "payments"}})
	cs.PrependReactor("list", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("configmaps"), "", nil)
	})

	snap, err := Take(context.Background(), cs)
	if err != nil {
		t.Fatalf("an optional collection failure must not fail the pass: %v", err)
	}
	if len(snap.Pods) != 1 {
		t.Errorf("the rest of the snapshot must still be collected, got %d pods", len(snap.Pods))
	}
	if !snap.Missing("configmaps") {
		t.Fatalf("configmaps failure not recorded: %+v", snap.Uncollected)
	}
	if snap.Missing("pods") {
		t.Error("pods collected fine but reported as missing")
	}
}

// TestCoreCollectionFailureAborts: the other half of the contract. A report without pods would
// describe an empty cluster, so it is never sent.
func TestCoreCollectionFailureAborts(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), "", nil)
	})

	if _, err := Take(context.Background(), cs); err == nil {
		t.Fatal("a core collection failure must fail the whole pass")
	}
}

func TestConfigMapsNeverNil(t *testing.T) {
	cs := fake.NewSimpleClientset()

	snap, err := Take(context.Background(), cs)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if snap.ConfigMaps == nil {
		t.Error("ConfigMaps is nil, want a non-nil (possibly empty) slice")
	}
}

// TestTakeCollectsResourceQuotasAndLimitRanges covers the platform-batch KG-QT-* additions:
// namespaced ResourceQuotas and LimitRanges are listed (full objects — they carry no sensitive
// payload, only resource ceilings/defaults) so resourcegov.go can tell which workload namespaces
// have a resource-governance boundary configured.
func TestTakeCollectsResourceQuotasAndLimitRanges(t *testing.T) {
	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "team-quota", Namespace: "payments"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4")},
		},
	}
	limitRange := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: "team-limits", Namespace: "payments"},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{{Type: corev1.LimitTypeContainer}},
		},
	}

	snap, err := Take(context.Background(), fake.NewSimpleClientset(quota, limitRange))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	if len(snap.ResourceQuotas) != 1 || snap.ResourceQuotas[0].Name != "team-quota" || snap.ResourceQuotas[0].Namespace != "payments" {
		t.Fatalf("expected the payments/team-quota ResourceQuota in the snapshot, got %+v", snap.ResourceQuotas)
	}
	if len(snap.LimitRanges) != 1 || snap.LimitRanges[0].Name != "team-limits" || snap.LimitRanges[0].Namespace != "payments" {
		t.Fatalf("expected the payments/team-limits LimitRange in the snapshot, got %+v", snap.LimitRanges)
	}
}

// TestTakeCollectsIngresses covers the platform-batch KG-IN-* addition: namespaced Ingresses are
// listed (full objects — they carry no sensitive payload, only host/path routing and tls refs) so
// ingress.go can tell which exposed hosts terminate TLS.
func TestTakeCollectsIngresses(t *testing.T) {
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "frontend"},
		Spec: networkingv1.IngressSpec{
			TLS:   []networkingv1.IngressTLS{{Hosts: []string{"app.example.com"}}},
			Rules: []networkingv1.IngressRule{{Host: "app.example.com"}},
		},
	}

	snap, err := Take(context.Background(), fake.NewSimpleClientset(ing))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	if len(snap.Ingresses) != 1 || snap.Ingresses[0].Name != "web" || snap.Ingresses[0].Namespace != "frontend" {
		t.Fatalf("expected the frontend/web Ingress in the snapshot, got %+v", snap.Ingresses)
	}
}

// TestTakeCollectsValidatingWebhookConfigs covers the KG-SU-004 addition: cluster-scoped
// ValidatingWebhookConfigurations are listed so the signature-verification check can detect
// admission stacks (sigstore policy-controller, Connaisseur, Kyverno) without a dynamic client.
func TestTakeCollectsValidatingWebhookConfigs(t *testing.T) {
	cfg := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "policy.sigstore.dev"},
		Webhooks:   []admissionregistrationv1.ValidatingWebhook{{Name: "policy.sigstore.dev"}},
	}

	snap, err := Take(context.Background(), fake.NewSimpleClientset(cfg))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	if len(snap.ValidatingWebhookConfigs) != 1 || snap.ValidatingWebhookConfigs[0].Name != "policy.sigstore.dev" {
		t.Fatalf("expected the policy.sigstore.dev webhook config in the snapshot, got %+v", snap.ValidatingWebhookConfigs)
	}
}
