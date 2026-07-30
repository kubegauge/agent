// resourcegov_test.go covers the KG-QT-* checks (resource-governance, resourcegov.go): each is a
// namespace-scoped structural existence check — warn when a non-system namespace lacks the
// governance object (ResourceQuota for KG-QT-001, LimitRange for KG-QT-002). Both share the same
// shape, so the table below drives them through a common helper.
package checks

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

func ns(name string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func TestNamespaceResourceQuotaCheck(t *testing.T) {
	cases := []struct {
		name          string
		namespaces    []corev1.Namespace
		quotas        []corev1.ResourceQuota
		wantStatus    string
		wantNS        []string
		wantResources []string
	}{
		{
			name:          "workload namespace with no quota",
			namespaces:    []corev1.Namespace{ns("payments")},
			quotas:        nil,
			wantStatus:    "warn",
			wantNS:        []string{"payments"},
			wantResources: []string{"namespace/payments"},
		},
		{
			name:       "workload namespace com quota",
			namespaces: []corev1.Namespace{ns("payments")},
			quotas: []corev1.ResourceQuota{
				{ObjectMeta: metav1.ObjectMeta{Name: "team-quota", Namespace: "payments"}},
			},
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name:          "system namespaces without quota are ignored",
			namespaces:    []corev1.Namespace{ns("kube-system"), ns("kube-public")},
			quotas:        nil,
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name:       "mistura: um coberto, outro descoberto (ordenado)",
			namespaces: []corev1.Namespace{ns("web"), ns("payments"), ns("kube-system")},
			quotas: []corev1.ResourceQuota{
				{ObjectMeta: metav1.ObjectMeta{Name: "q", Namespace: "payments"}},
			},
			wantStatus:    "warn",
			wantNS:        []string{"web"},
			wantResources: []string{"namespace/web"},
		},
		{
			name:          "cluster with no workload namespaces",
			namespaces:    nil,
			quotas:        nil,
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := &snapshot.Snapshot{Namespaces: tc.namespaces, ResourceQuotas: tc.quotas}
			res := namespaceResourceQuotaCheck{}.Run(snap)
			assertNamespaceResult(t, res, tc.wantStatus, tc.wantNS, tc.wantResources)
		})
	}
}

func TestNamespaceLimitRangeCheck(t *testing.T) {
	cases := []struct {
		name          string
		namespaces    []corev1.Namespace
		limitRanges   []corev1.LimitRange
		wantStatus    string
		wantNS        []string
		wantResources []string
	}{
		{
			name:          "workload namespace with no limitrange",
			namespaces:    []corev1.Namespace{ns("payments")},
			limitRanges:   nil,
			wantStatus:    "warn",
			wantNS:        []string{"payments"},
			wantResources: []string{"namespace/payments"},
		},
		{
			name:       "workload namespace com limitrange",
			namespaces: []corev1.Namespace{ns("payments")},
			limitRanges: []corev1.LimitRange{
				{ObjectMeta: metav1.ObjectMeta{Name: "team-limits", Namespace: "payments"}},
			},
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name:          "system namespace without limitrange is ignored",
			namespaces:    []corev1.Namespace{ns("kube-system")},
			limitRanges:   nil,
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name:       "mistura: um coberto, outro descoberto (ordenado)",
			namespaces: []corev1.Namespace{ns("web"), ns("payments")},
			limitRanges: []corev1.LimitRange{
				{ObjectMeta: metav1.ObjectMeta{Name: "lr", Namespace: "web"}},
			},
			wantStatus:    "warn",
			wantNS:        []string{"payments"},
			wantResources: []string{"namespace/payments"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := &snapshot.Snapshot{Namespaces: tc.namespaces, LimitRanges: tc.limitRanges}
			res := namespaceLimitRangeCheck{}.Run(snap)
			assertNamespaceResult(t, res, tc.wantStatus, tc.wantNS, tc.wantResources)
		})
	}
}

func assertNamespaceResult(t *testing.T, res Result, wantStatus string, wantNS, wantResources []string) {
	t.Helper()
	if res.Status != wantStatus {
		t.Errorf("Status = %q, want %q", res.Status, wantStatus)
	}
	if !reflect.DeepEqual(res.Namespaces, wantNS) {
		t.Errorf("Namespaces = %v, want %v", res.Namespaces, wantNS)
	}
	if !reflect.DeepEqual(res.AffectedResources, wantResources) {
		t.Errorf("AffectedResources = %v, want %v", res.AffectedResources, wantResources)
	}
}

func TestResourceGovernanceCheckIDs(t *testing.T) {
	if got := (namespaceResourceQuotaCheck{}).ID(); got != "KG-QT-001" {
		t.Errorf("ID() = %q, want KG-QT-001", got)
	}
	if got := (namespaceLimitRangeCheck{}).ID(); got != "KG-QT-002" {
		t.Errorf("ID() = %q, want KG-QT-002", got)
	}
}
