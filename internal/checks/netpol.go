// netpol.go implements the KG-NP-* checks (NetworkPolicy posture): default-deny ingress/egress
// coverage per namespace, an ingress-restricting policy in kube-system, CNI NetworkPolicy
// support, and open ipBlock ranges in allow rules.
//
// Every mock KG-NP-* id (001-005) turned out to be computable from the M2 snapshot; none were
// left out.
//
//   - KG-NP-002 ("critical namespaces must restrict egress"): the mock scopes this to
//     "critical" namespaces (e.g. "payments" in the demo data), a classification with no signal
//     on a real cluster (no generic label/annotation identifies "criticality"). We apply the same
//     default-deny-egress test to every non-system namespace instead — the exact mechanism
//     PLAN-FASE-2.md §6 lists as computable (default-deny egress per namespace), just without
//     the (undecidable) namespace-criticality filter.
//   - KG-NP-004 ("kube-system protected from workload access") is implemented as a
//     structural existence check — "does kube-system have at least one Ingress-type
//     NetworkPolicy" — rather than a full traffic-semantics evaluation of which pods can actually
//     reach kube-system; that engine is explicitly deferred to M5 (PLAN-FASE-2.md §8). This
//     mirrors the mock's own auditCommand, which is also just `kubectl get netpol -n kube-system`
//     with no semantic evaluation.
package checks

import (
	"sort"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// netpolsByNamespace indexes a snapshot's NetworkPolicies by namespace (shared by the checks
// below).
func netpolsByNamespace(snap *snapshot.Snapshot) map[string][]networkingv1.NetworkPolicy {
	idx := map[string][]networkingv1.NetworkPolicy{}
	for _, np := range snap.NetworkPolicies {
		idx[np.Namespace] = append(idx[np.Namespace], np)
	}
	return idx
}

// workloadNamespaceNames returns every namespace name in the snapshot excluding system
// namespaces, sorted for deterministic Result output.
func workloadNamespaceNames(snap *snapshot.Snapshot) []string {
	names := make([]string, 0, len(snap.Namespaces))
	for _, ns := range snap.Namespaces {
		if isSystemNamespace(ns.Name) {
			continue
		}
		names = append(names, ns.Name)
	}
	sort.Strings(names)
	return names
}

// namespaceResult builds a Result from a list of violating namespace names: status is
// failStatus when non-empty, "pass" when empty. AffectedResources mirrors each namespace as
// "namespace/<ns>" (the mock's own affectedResources convention for namespace-scoped findings).
func namespaceResult(violating []string, failStatus string) Result {
	if len(violating) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	resources := make([]string, 0, len(violating))
	for _, ns := range violating {
		resources = append(resources, "namespace/"+ns)
	}
	return Result{Status: failStatus, Namespaces: violating, AffectedResources: resources}
}

// ---- KG-NP-001: default-deny ingress per namespace -------------------------------------------

type defaultDenyIngressCheck struct{}

func (defaultDenyIngressCheck) ID() string { return "KG-NP-001" }

// Run flags every non-system namespace lacking a default-deny-ingress NetworkPolicy (reusing
// report.DefaultDeny, the exact same definition namespaces.ts's NamespaceInfo.hasDefaultDenyIngress
// is built from). System namespaces (kube-system/kube-public/kube-node-lease/local-path-storage)
// are excluded: denying all ingress there by default would break DNS, the API server's own
// components, and CNI/node agents that legitimately need to reach or be reached within
// kube-system.
func (defaultDenyIngressCheck) Run(snap *snapshot.Snapshot) Result {
	byNs := netpolsByNamespace(snap)
	missing := []string{}
	for _, name := range workloadNamespaceNames(snap) {
		ingress, _ := report.DefaultDeny(byNs[name])
		if !ingress {
			missing = append(missing, name)
		}
	}
	return namespaceResult(missing, "fail")
}

// ---- KG-NP-002: default-deny egress per namespace ---------------------------------------------

type defaultDenyEgressCheck struct{}

func (defaultDenyEgressCheck) ID() string { return "KG-NP-002" }

// Run: see the package doc comment above for why this drops the mock's "critical namespaces"
// scoping and applies to every non-system namespace instead.
func (defaultDenyEgressCheck) Run(snap *snapshot.Snapshot) Result {
	byNs := netpolsByNamespace(snap)
	missing := []string{}
	for _, name := range workloadNamespaceNames(snap) {
		_, egress := report.DefaultDeny(byNs[name])
		if !egress {
			missing = append(missing, name)
		}
	}
	return namespaceResult(missing, "fail")
}

// ---- KG-NP-003: CNI support for NetworkPolicy --------------------------------------------------

type cniSupportCheck struct{}

func (cniSupportCheck) ID() string { return "KG-NP-003" }

// classifyCNI matches a lowercased kube-system DaemonSet name against known CNI names. flannel
// and kindnet are known NOT to enforce NetworkPolicy (accepted by the API, silently ignored);
// calico and cilium do. known is false when the name doesn't match any recognized CNI.
func classifyCNI(lowerName string) (supportsNetpol bool, known bool) {
	switch {
	case strings.Contains(lowerName, "calico"), strings.Contains(lowerName, "cilium"):
		return true, true
	case strings.Contains(lowerName, "flannel"), strings.Contains(lowerName, "kindnet"):
		return false, true
	default:
		return false, false
	}
}

// Run inspects kube-system DaemonSet names for a recognized CNI: pass when a NetworkPolicy-
// capable CNI is found, warn when only a non-enforcing CNI is found (flannel/kindnet), info when
// nothing recognized is running — we genuinely can't tell either way, so this is never a false
// "fail".
func (cniSupportCheck) Run(snap *snapshot.Snapshot) Result {
	var supporting, nonSupporting []string
	for _, ds := range snap.DaemonSets {
		if ds.Namespace != "kube-system" {
			continue
		}
		supports, known := classifyCNI(strings.ToLower(ds.Name))
		if !known {
			continue
		}
		if supports {
			supporting = append(supporting, ds.Name)
		} else {
			nonSupporting = append(nonSupporting, ds.Name)
		}
	}

	switch {
	case len(supporting) > 0:
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: prefixedSorted("daemonset/kube-system/", supporting)}
	case len(nonSupporting) > 0:
		return Result{Status: "warn", Namespaces: []string{}, AffectedResources: prefixedSorted("daemonset/kube-system/", nonSupporting)}
	default:
		return Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}}
	}
}

func prefixedSorted(prefix string, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, prefix+n)
	}
	sort.Strings(out)
	return out
}

// ---- KG-NP-004: kube-system protected against workload ingress --------------------------------

type kubeSystemIngressProtectedCheck struct{}

func (kubeSystemIngressProtectedCheck) ID() string { return "KG-NP-004" }

// Run: warn (not fail — a soft hardening recommendation, matching the mock's own medium
// severity) when kube-system has no Ingress-type NetworkPolicy at all. See the package doc
// comment for why this is a structural existence check rather than a semantic evaluation.
func (kubeSystemIngressProtectedCheck) Run(snap *snapshot.Snapshot) Result {
	for _, np := range snap.NetworkPolicies {
		if np.Namespace != "kube-system" {
			continue
		}
		for _, t := range np.Spec.PolicyTypes {
			if t == networkingv1.PolicyTypeIngress {
				return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{"namespace/kube-system"}}
			}
		}
	}
	return Result{Status: "warn", Namespaces: []string{"kube-system"}, AffectedResources: []string{"namespace/kube-system"}}
}

// ---- KG-NP-005: no 0.0.0.0/0 ipBlock in allow rules --------------------------------------------

type ipBlockOpenCheck struct{}

func (ipBlockOpenCheck) ID() string { return "KG-NP-005" }

const openCIDR = "0.0.0.0/0"

// Run flags any NetworkPolicy with an ipBlock allow rule spanning all of IPv4 (0.0.0.0/0) in
// either direction — this negates segmentation regardless of any other selector in the policy.
func (ipBlockOpenCheck) Run(snap *snapshot.Snapshot) Result {
	var offenders []string
	for _, np := range snap.NetworkPolicies {
		open := false
		for _, rule := range np.Spec.Ingress {
			for _, peer := range rule.From {
				if peer.IPBlock != nil && peer.IPBlock.CIDR == openCIDR {
					open = true
				}
			}
		}
		for _, rule := range np.Spec.Egress {
			for _, peer := range rule.To {
				if peer.IPBlock != nil && peer.IPBlock.CIDR == openCIDR {
					open = true
				}
			}
		}
		if open {
			offenders = append(offenders, "networkpolicy/"+np.Namespace+"/"+np.Name)
		}
	}
	if len(offenders) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(offenders)
	return Result{Status: "fail", Namespaces: []string{}, AffectedResources: offenders}
}
