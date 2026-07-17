// resourcegov.go implements the KG-QT-* checks (Resource Governance): whether each workload
// namespace carries a resource-governance boundary — a ResourceQuota capping the namespace's
// aggregate consumption (KG-QT-001) and a LimitRange supplying per-container defaults and bounds
// (KG-QT-002).
//
// Both are namespace-scoped structural existence checks and warn (not fail) when the object is
// absent: they are recommended hardening controls (the NSA/CISA hardening guide's "resource
// policies"), the same soft-recommendation posture as KG-NP-004. They are the namespace-level
// complement to KG-SC-005 (secctx.go), which flags individual workloads missing resources.limits:
// a LimitRange is precisely what makes those limits appear by default, and a ResourceQuota is the
// multi-tenant / anti-resource-exhaustion (MITRE T1496) ceiling that a per-workload limit alone
// cannot provide. System namespaces are excluded (workloadNamespaceNames) — quotas/limits there
// are the distribution's concern, not the operator's.
package checks

import (
	"github.com/kubegauge/agent/internal/snapshot"
)

// namespacesWithoutGovernance returns the workload namespaces (system namespaces excluded, sorted
// by workloadNamespaceNames) absent from covered — the set of namespaces that carry the governance
// object being checked.
func namespacesWithoutGovernance(snap *snapshot.Snapshot, covered map[string]bool) []string {
	missing := []string{}
	for _, name := range workloadNamespaceNames(snap) {
		if !covered[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// ---- KG-QT-001: ResourceQuota per namespace ---------------------------------------------------

type namespaceResourceQuotaCheck struct{}

func (namespaceResourceQuotaCheck) ID() string { return "KG-QT-001" }

// Run warns for every non-system namespace with no ResourceQuota: without one, a single namespace
// can consume the whole cluster's CPU/memory (or object count), turning one compromised or runaway
// workload into a cluster-wide denial of service.
func (namespaceResourceQuotaCheck) Run(snap *snapshot.Snapshot) Result {
	covered := map[string]bool{}
	for _, rq := range snap.ResourceQuotas {
		covered[rq.Namespace] = true
	}
	return namespaceResult(namespacesWithoutGovernance(snap, covered), "warn")
}

// ---- KG-QT-002: LimitRange per namespace ------------------------------------------------------

type namespaceLimitRangeCheck struct{}

func (namespaceLimitRangeCheck) ID() string { return "KG-QT-002" }

// Run warns for every non-system namespace with no LimitRange: without one, pods created without an
// explicit resources.limits get no default ceiling at all (KG-SC-005 will then flag each such
// workload individually) — the LimitRange is the namespace-wide safety net that guarantees a
// default even when a manifest forgets it.
func (namespaceLimitRangeCheck) Run(snap *snapshot.Snapshot) Result {
	covered := map[string]bool{}
	for _, lr := range snap.LimitRanges {
		covered[lr.Namespace] = true
	}
	return namespaceResult(namespacesWithoutGovernance(snap, covered), "warn")
}
