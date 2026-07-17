// namespace_test.go table-tests default-deny NetworkPolicy detection and PSA label parsing.
package report

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDefaultDeny(t *testing.T) {
	tests := []struct {
		name        string
		policies    []networkingv1.NetworkPolicy
		wantIngress bool
		wantEgress  bool
	}{
		{name: "no policies", policies: nil, wantIngress: false, wantEgress: false},
		{
			name: "non-empty selector does not count as default-deny",
			policies: []networkingv1.NetworkPolicy{{Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			}}},
			wantIngress: false, wantEgress: false,
		},
		{
			name: "empty selector + ingress type + no rules = default-deny ingress",
			policies: []networkingv1.NetworkPolicy{{Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			}}},
			wantIngress: true, wantEgress: false,
		},
		{
			name: "empty selector + ingress type + has allow rule = not default-deny",
			policies: []networkingv1.NetworkPolicy{{Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
			}}},
			wantIngress: false, wantEgress: false,
		},
		{
			name: "empty selector + egress type + no rules = default-deny egress",
			policies: []networkingv1.NetworkPolicy{{Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			}}},
			wantIngress: false, wantEgress: true,
		},
		{
			name: "empty selector + both types + no rules = default-deny both",
			policies: []networkingv1.NetworkPolicy{{Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			}}},
			wantIngress: true, wantEgress: true,
		},
		{
			name: "two policies combine via OR across the namespace",
			policies: []networkingv1.NetworkPolicy{
				{Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}},
				{Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}}},
			},
			wantIngress: true, wantEgress: true,
		},
		{
			name: "empty selector via explicit-empty matchExpressions too",
			policies: []networkingv1.NetworkPolicy{{Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{}, MatchExpressions: []metav1.LabelSelectorRequirement{}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			}}},
			wantIngress: true, wantEgress: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIngress, gotEgress := DefaultDeny(tt.policies)
			if gotIngress != tt.wantIngress || gotEgress != tt.wantEgress {
				t.Errorf("DefaultDeny() = (%v, %v), want (%v, %v)", gotIngress, gotEgress, tt.wantIngress, tt.wantEgress)
			}
		})
	}
}

func TestPsaLabel(t *testing.T) {
	labels := map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}

	if got := psaLabel(labels, "enforce"); got == nil || *got != "restricted" {
		t.Errorf("psaLabel(enforce) = %v, want pointer to \"restricted\"", got)
	}
	if got := psaLabel(labels, "audit"); got != nil {
		t.Errorf("psaLabel(audit) = %v, want nil", *got)
	}
	if got := psaLabel(nil, "warn"); got != nil {
		t.Errorf("psaLabel(nil labels) = %v, want nil", *got)
	}
}
