// namespace.go builds NamespaceInfo entries: PSA labels, pod counts, and default-deny detection.
package report

import (
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// BuildNamespaces assembles one NamespaceInfo per namespace in the snapshot.
func BuildNamespaces(snap *snapshot.Snapshot) []NamespaceInfo {
	result := make([]NamespaceInfo, 0, len(snap.Namespaces))

	podCountByNs := map[string]int{}
	for _, p := range snap.Pods {
		podCountByNs[p.Namespace]++
	}

	netpolsByNs := map[string][]networkingv1.NetworkPolicy{}
	for _, np := range snap.NetworkPolicies {
		netpolsByNs[np.Namespace] = append(netpolsByNs[np.Namespace], np)
	}

	for _, ns := range snap.Namespaces {
		ingress, egress := DefaultDeny(netpolsByNs[ns.Name])

		result = append(result, NamespaceInfo{
			Name:                  ns.Name,
			PsaEnforce:            psaLabel(ns.Labels, "enforce"),
			PsaAudit:              psaLabel(ns.Labels, "audit"),
			PsaWarn:               psaLabel(ns.Labels, "warn"),
			PodCount:              podCountByNs[ns.Name],
			HasDefaultDenyIngress: ingress,
			HasDefaultDenyEgress:  egress,
		})
	}

	return result
}

// psaLabel reads a pod-security.kubernetes.io/{mode} label; absent -> nil (B5).
func psaLabel(labels map[string]string, mode string) *string {
	v, ok := labels["pod-security.kubernetes.io/"+mode]
	if !ok {
		return nil
	}
	return &v
}

// DefaultDeny reports whether the namespace's NetworkPolicies include a default-deny-ingress
// and/or default-deny-egress policy: empty podSelector (matches all pods) + the corresponding
// policyType + no allow rules for that direction (B5/orchestrator guidance). Exported (B5 kept it
// package-private; M2 promotes it) so internal/checks/netpol.go can reuse the exact same
// definition of "default-deny" for KG-NP-001/002 instead of re-deriving it — see that file.
func DefaultDeny(policies []networkingv1.NetworkPolicy) (ingress bool, egress bool) {
	for _, np := range policies {
		emptySelector := len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0
		if !emptySelector {
			continue
		}

		hasIngressType := false
		hasEgressType := false
		for _, t := range np.Spec.PolicyTypes {
			switch t {
			case networkingv1.PolicyTypeIngress:
				hasIngressType = true
			case networkingv1.PolicyTypeEgress:
				hasEgressType = true
			}
		}

		if hasIngressType && len(np.Spec.Ingress) == 0 {
			ingress = true
		}
		if hasEgressType && len(np.Spec.Egress) == 0 {
			egress = true
		}
	}
	return ingress, egress
}
