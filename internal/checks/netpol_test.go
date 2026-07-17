// netpol_test.go table-tests the KG-NP-* checks (netpol.go) against hand-built snapshot fixtures.
package checks

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

func defaultDenyPolicy(namespace, name string, direction networkingv1.PolicyType) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{direction},
		},
	}
}

func TestDefaultDenyIngressCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "namespace with default-deny ingress passes",
			snap: &snapshot.Snapshot{
				Namespaces:      []corev1.Namespace{testNamespace("default", nil)},
				NetworkPolicies: []networkingv1.NetworkPolicy{defaultDenyPolicy("default", "deny-all-ingress", networkingv1.PolicyTypeIngress)},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "namespace without any netpol fails",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{testNamespace("default", nil)},
			},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"namespace/default"}},
		},
		{
			name: "non-empty-selector netpol does not count as default-deny",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{testNamespace("default", nil)},
				NetworkPolicies: []networkingv1.NetworkPolicy{{
					ObjectMeta: metav1.ObjectMeta{Name: "app-only", Namespace: "default"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					},
				}},
			},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"namespace/default"}},
		},
		{
			name: "kube-system without any netpol is excluded (system namespace)",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{testNamespace("kube-system", nil)},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "mixed: one compliant namespace, one missing",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{testNamespace("default", nil), testNamespace("payments", nil)},
				NetworkPolicies: []networkingv1.NetworkPolicy{
					defaultDenyPolicy("default", "deny-all-ingress", networkingv1.PolicyTypeIngress),
				},
			},
			want: Result{Status: "fail", Namespaces: []string{"payments"}, AffectedResources: []string{"namespace/payments"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (defaultDenyIngressCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDefaultDenyEgressCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "namespace with default-deny egress passes",
			snap: &snapshot.Snapshot{
				Namespaces:      []corev1.Namespace{testNamespace("payments", nil)},
				NetworkPolicies: []networkingv1.NetworkPolicy{defaultDenyPolicy("payments", "deny-all-egress", networkingv1.PolicyTypeEgress)},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "namespace with only an ingress default-deny still fails egress check",
			snap: &snapshot.Snapshot{
				Namespaces:      []corev1.Namespace{testNamespace("payments", nil)},
				NetworkPolicies: []networkingv1.NetworkPolicy{defaultDenyPolicy("payments", "deny-all-ingress", networkingv1.PolicyTypeIngress)},
			},
			want: Result{Status: "fail", Namespaces: []string{"payments"}, AffectedResources: []string{"namespace/payments"}},
		},
		{
			name: "kube-system excluded regardless of egress policy",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{testNamespace("kube-system", nil)},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (defaultDenyEgressCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func cniDaemonSet(name string) appsv1.DaemonSet {
	return appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system"}}
}

func TestCNISupportCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "calico present passes",
			snap: &snapshot.Snapshot{DaemonSets: []appsv1.DaemonSet{cniDaemonSet("calico-node")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{"daemonset/kube-system/calico-node"}},
		},
		{
			name: "cilium present passes",
			snap: &snapshot.Snapshot{DaemonSets: []appsv1.DaemonSet{cniDaemonSet("cilium")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{"daemonset/kube-system/cilium"}},
		},
		{
			name: "flannel present warns (does not enforce NetworkPolicy)",
			snap: &snapshot.Snapshot{DaemonSets: []appsv1.DaemonSet{cniDaemonSet("kube-flannel-ds")}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"daemonset/kube-system/kube-flannel-ds"}},
		},
		{
			name: "kindnet present warns",
			snap: &snapshot.Snapshot{DaemonSets: []appsv1.DaemonSet{cniDaemonSet("kindnet")}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"daemonset/kube-system/kindnet"}},
		},
		{
			name: "nothing recognized yields info, never a false fail",
			snap: &snapshot.Snapshot{DaemonSets: []appsv1.DaemonSet{cniDaemonSet("some-custom-agent")}},
			want: Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "no daemonsets at all yields info",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "daemonset outside kube-system is ignored",
			snap: &snapshot.Snapshot{DaemonSets: []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: "calico-system"}}}},
			want: Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "calico takes priority over flannel when both are present",
			snap: &snapshot.Snapshot{DaemonSets: []appsv1.DaemonSet{cniDaemonSet("kube-flannel-ds"), cniDaemonSet("calico-node")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{"daemonset/kube-system/calico-node"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (cniSupportCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestKubeSystemIngressProtectedCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "ingress-type netpol in kube-system passes",
			snap: &snapshot.Snapshot{NetworkPolicies: []networkingv1.NetworkPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "restrict-ingress", Namespace: "kube-system"},
				Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{"namespace/kube-system"}},
		},
		{
			name: "only an egress-type netpol in kube-system still warns",
			snap: &snapshot.Snapshot{NetworkPolicies: []networkingv1.NetworkPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "restrict-egress", Namespace: "kube-system"},
				Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}},
			}}},
			want: Result{Status: "warn", Namespaces: []string{"kube-system"}, AffectedResources: []string{"namespace/kube-system"}},
		},
		{
			name: "no netpol at all in kube-system warns",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "warn", Namespaces: []string{"kube-system"}, AffectedResources: []string{"namespace/kube-system"}},
		},
		{
			name: "netpol in a different namespace doesn't count",
			snap: &snapshot.Snapshot{NetworkPolicies: []networkingv1.NetworkPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "restrict-ingress", Namespace: "default"},
				Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}},
			}}},
			want: Result{Status: "warn", Namespaces: []string{"kube-system"}, AffectedResources: []string{"namespace/kube-system"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (kubeSystemIngressProtectedCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestIPBlockOpenCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no netpols passes",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "ingress ipBlock 0.0.0.0/0 fails",
			snap: &snapshot.Snapshot{NetworkPolicies: []networkingv1.NetworkPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "open-ingress", Namespace: "default"},
				Spec: networkingv1.NetworkPolicySpec{
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}},
					}},
				},
			}}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"networkpolicy/default/open-ingress"}},
		},
		{
			name: "egress ipBlock 0.0.0.0/0 fails",
			snap: &snapshot.Snapshot{NetworkPolicies: []networkingv1.NetworkPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "open-egress", Namespace: "default"},
				Spec: networkingv1.NetworkPolicySpec{
					Egress: []networkingv1.NetworkPolicyEgressRule{{
						To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}},
					}},
				},
			}}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"networkpolicy/default/open-egress"}},
		},
		{
			name: "scoped ipBlock CIDR passes",
			snap: &snapshot.Snapshot{NetworkPolicies: []networkingv1.NetworkPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "scoped", Namespace: "default"},
				Spec: networkingv1.NetworkPolicySpec{
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}}},
					}},
				},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (ipBlockOpenCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
