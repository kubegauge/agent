// ingress.go implements the KG-IN-* checks (Ingress Exposure): whether the hosts an Ingress
// exposes actually terminate TLS. KG-IN-001 warns for every Ingress whose routed hosts are not all
// covered by a spec.tls block — plaintext HTTP exposure lets credentials, session tokens and data
// travel in the clear, sniffable on the path to the cluster (MITRE T1040).
//
// This is a warn (not fail): the Ingress object alone cannot tell us whether TLS is instead
// terminated upstream (an external load balancer, CDN or service mesh), so — following the same
// "don't emit a false fail when we genuinely can't be sure" posture as netpol.go/versions.go — the
// check flags the exposure for review rather than asserting a breach. Ingresses are inspected in
// every namespace (no system-namespace exclusion): an Ingress is an explicit act of external
// exposure, and its namespace does not change whether the traffic is plaintext.
package checks

import (
	"sort"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// ingressTerminatesTLS reports whether every host routed by ing is covered by a TLS block. A TLS
// block with no Hosts is the default-certificate catch-all (covers every host); otherwise each
// spec.rules[].host must appear among the listed TLS hosts. An Ingress with no TLS block at all is
// necessarily plaintext.
func ingressTerminatesTLS(ing networkingv1.Ingress) bool {
	if len(ing.Spec.TLS) == 0 {
		return false
	}
	tlsHosts := map[string]bool{}
	for _, t := range ing.Spec.TLS {
		if len(t.Hosts) == 0 {
			return true // default-certificate TLS block: covers every host
		}
		for _, h := range t.Hosts {
			tlsHosts[h] = true
		}
	}
	for _, r := range ing.Spec.Rules {
		if r.Host == "" || !tlsHosts[r.Host] {
			return false
		}
	}
	return true
}

// ---- KG-IN-001: Ingress must terminate TLS ----------------------------------------------------

type ingressTLSCheck struct{}

func (ingressTLSCheck) ID() string { return "KG-IN-001" }

func (ingressTLSCheck) Run(snap *snapshot.Snapshot) Result {
	var offenders []string
	nsSet := map[string]bool{}
	for _, ing := range snap.Ingresses {
		if !ingressTerminatesTLS(ing) {
			offenders = append(offenders, "ingress/"+ing.Namespace+"/"+ing.Name)
			nsSet[ing.Namespace] = true
		}
	}
	if len(offenders) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(offenders)
	return Result{Status: "warn", Namespaces: sortedKeys(nsSet), AffectedResources: offenders}
}
