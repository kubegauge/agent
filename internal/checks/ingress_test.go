// ingress_test.go covers KG-IN-001 (ingress-exposure, ingress.go): warn for every Ingress whose
// routed hosts are not all covered by a TLS block. Verdict is a pure function of each Ingress's
// spec.tls / spec.rules, so the table below builds Ingress fixtures directly as struct literals.
package checks

import (
	"reflect"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

func ingress(namespace, name string, tls []networkingv1.IngressTLS, hosts ...string) networkingv1.Ingress {
	rules := make([]networkingv1.IngressRule, 0, len(hosts))
	for _, h := range hosts {
		rules = append(rules, networkingv1.IngressRule{Host: h})
	}
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       networkingv1.IngressSpec{TLS: tls, Rules: rules},
	}
}

func TestIngressTLSCheck(t *testing.T) {
	cases := []struct {
		name          string
		ingresses     []networkingv1.Ingress
		wantStatus    string
		wantNS        []string
		wantResources []string
	}{
		{
			name: "ingress com TLS cobrindo o host",
			ingresses: []networkingv1.Ingress{
				ingress("frontend", "web", []networkingv1.IngressTLS{{Hosts: []string{"app.example.com"}}}, "app.example.com"),
			},
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name: "ingress with no TLS block",
			ingresses: []networkingv1.Ingress{
				ingress("frontend", "web", nil, "app.example.com"),
			},
			wantStatus:    "warn",
			wantNS:        []string{"frontend"},
			wantResources: []string{"ingress/frontend/web"},
		},
		{
			name: "a TLS block with no hosts covers everything (default cert)",
			ingresses: []networkingv1.Ingress{
				ingress("frontend", "web", []networkingv1.IngressTLS{{}}, "app.example.com", "api.example.com"),
			},
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name: "TLS covers one host while another stays in cleartext",
			ingresses: []networkingv1.Ingress{
				ingress("frontend", "web", []networkingv1.IngressTLS{{Hosts: []string{"app.example.com"}}}, "app.example.com", "admin.example.com"),
			},
			wantStatus:    "warn",
			wantNS:        []string{"frontend"},
			wantResources: []string{"ingress/frontend/web"},
		},
		{
			name: "mix of several ingresses (sorted)",
			ingresses: []networkingv1.Ingress{
				ingress("frontend", "web", []networkingv1.IngressTLS{{Hosts: []string{"app.example.com"}}}, "app.example.com"),
				ingress("shop", "checkout", nil, "checkout.example.com"),
				ingress("frontend", "legacy", nil, "legacy.example.com"),
			},
			wantStatus:    "warn",
			wantNS:        []string{"frontend", "shop"},
			wantResources: []string{"ingress/frontend/legacy", "ingress/shop/checkout"},
		},
		{
			name:          "cluster with no ingresses",
			ingresses:     nil,
			wantStatus:    "pass",
			wantNS:        []string{},
			wantResources: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ingressTLSCheck{}.Run(&snapshot.Snapshot{Ingresses: tc.ingresses})
			if res.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", res.Status, tc.wantStatus)
			}
			if !reflect.DeepEqual(res.Namespaces, tc.wantNS) {
				t.Errorf("Namespaces = %v, want %v", res.Namespaces, tc.wantNS)
			}
			if !reflect.DeepEqual(res.AffectedResources, tc.wantResources) {
				t.Errorf("AffectedResources = %v, want %v", res.AffectedResources, tc.wantResources)
			}
		})
	}
}

func TestIngressTLSCheckID(t *testing.T) {
	if got := (ingressTLSCheck{}).ID(); got != "KG-IN-001" {
		t.Errorf("ID() = %q, want KG-IN-001", got)
	}
}
