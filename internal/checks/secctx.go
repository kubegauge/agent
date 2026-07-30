// secctx.go implements the KG-SC-* checks (container SecurityContext posture): runAsNonRoot,
// readOnlyRootFilesystem, capabilities.drop ALL, allowPrivilegeEscalation and resource limits —
// evaluated over the same pod-template sources workload.go already builds for WorkloadPosture
// (Deployment/StatefulSet/DaemonSet pod templates + ownerReferences-less Pods).
//
// KG-SC-001/002/003/004 reuse report.BuildWorkloads directly: its worst-of-containers aggregation
// (report/workload.go) already computes exactly the four booleans these checks need per workload
// (RunAsNonRoot, ReadOnlyRootFilesystem, CapabilitiesDropAll, AllowPrivilegeEscalation), so
// recomputing them here would duplicate that logic rather than reuse it. One consequence inherited
// from that aggregation: like WorkloadPosture itself, these four only inspect spec.Containers, not
// spec.InitContainers (see workload.go's aggregatePosture) — a pre-existing M1 scope limit, not
// something introduced here.
//
// KG-SC-005 (resource limits) needs raw container data (resources.limits) WorkloadPosture does not
// keep, so it uses report.WorkloadSources instead and inspects every container AND init container
// directly (a check written from scratch has no reason to inherit the init-container gap above).
//
// All five checks exclude system namespaces (kube-system/kube-public/kube-node-lease/
// local-path-storage), consistent with every M2 pod/workload-level check (psa.go): these
// namespaces are owned by the cluster distribution, not the workload team the dashboard is for.
//
// All five mock ids (KG-SC-001..005) turned out to be computable; none were left out.
package checks

import (
	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// ---- KG-SC-001: runAsNonRoot ---------------------------------------------------------------

type runAsNonRootCheck struct{}

func (runAsNonRootCheck) ID() string { return "KG-SC-001" }

// Run flags every workload (outside system namespaces) whose worst-of-containers RunAsNonRoot is
// false — i.e. at least one container neither sets runAsNonRoot: true itself nor inherits it from
// the pod, matching the mock's own root-cause: "runAsNonRoot: true makes the kubelet REFUSE to start the
// container". A hard, deterministic fail: there is no legitimate exception mirrored in the mock.
func (runAsNonRootCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, w := range report.BuildWorkloads(snap) {
		if isSystemNamespace(w.Namespace) {
			continue
		}
		if !w.RunAsNonRoot {
			resources = append(resources, workloadResourceRef(w.Kind, w.Namespace, w.Name))
			nsSet[w.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "fail")
}

// ---- KG-SC-002: readOnlyRootFilesystem -----------------------------------------------------

type readOnlyRootFilesystemCheck struct{}

func (readOnlyRootFilesystemCheck) ID() string { return "KG-SC-002" }

// Run flags every workload (outside system namespaces) whose worst-of-containers
// ReadOnlyRootFilesystem is false. Deterministic fail, same rationale as KG-SC-001.
func (readOnlyRootFilesystemCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, w := range report.BuildWorkloads(snap) {
		if isSystemNamespace(w.Namespace) {
			continue
		}
		if !w.ReadOnlyRootFilesystem {
			resources = append(resources, workloadResourceRef(w.Kind, w.Namespace, w.Name))
			nsSet[w.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "fail")
}

// ---- KG-SC-003: capabilities.drop ALL --------------------------------------------------------

type capabilitiesDropAllCheck struct{}

func (capabilitiesDropAllCheck) ID() string { return "KG-SC-003" }

// Run flags every workload (outside system namespaces) whose worst-of-containers
// CapabilitiesDropAll is false, as a warn rather than a fail: unlike KG-SC-001/002/004, dropping
// every capability sometimes needs a documented exception (the mock's own remediation calls out
// re-adding NET_BIND_SERVICE for privileged ports) — a case-by-case review signal, matching the
// "warn" status the mock itself assigns this id (same pattern as psa.go's hostPath check).
func (capabilitiesDropAllCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, w := range report.BuildWorkloads(snap) {
		if isSystemNamespace(w.Namespace) {
			continue
		}
		if !w.CapabilitiesDropAll {
			resources = append(resources, workloadResourceRef(w.Kind, w.Namespace, w.Name))
			nsSet[w.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "warn")
}

// ---- KG-SC-004: allowPrivilegeEscalation=false ------------------------------------------------

type allowPrivilegeEscalationCheck struct{}

func (allowPrivilegeEscalationCheck) ID() string { return "KG-SC-004" }

// Run flags every workload (outside system namespaces) whose worst-of-containers
// AllowPrivilegeEscalation is true (the K8s default when unset). Deterministic fail — the mock's
// own explanation notes this control comes "at no cost for most apps" (no legitimate
// exception to weigh against, unlike KG-SC-003's capabilities).
func (allowPrivilegeEscalationCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, w := range report.BuildWorkloads(snap) {
		if isSystemNamespace(w.Namespace) {
			continue
		}
		if w.AllowPrivilegeEscalation {
			resources = append(resources, workloadResourceRef(w.Kind, w.Namespace, w.Name))
			nsSet[w.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "fail")
}

// ---- KG-SC-005: resource limits (CPU/memory) --------------------------------------------------

type resourceLimitsCheck struct{}

func (resourceLimitsCheck) ID() string { return "KG-SC-005" }

// Run flags every workload (outside system namespaces) with at least one container or init
// container missing resources.limits entirely — mirroring the mock's own audit command
// (`select(.resources.limits == null)`), which does not distinguish "missing cpu" from "missing
// memory" from "missing the whole limits object", just presence/absence. Deterministic fail: the
// field is either set or it isn't, no case-by-case judgment involved (unlike KG-SC-003).
func (resourceLimitsCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, src := range report.WorkloadSources(snap) {
		if isSystemNamespace(src.Namespace) {
			continue
		}
		if workloadMissingResourceLimits(src) {
			resources = append(resources, workloadResourceRef(src.Kind, src.Namespace, src.Name))
			nsSet[src.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "fail")
}

// workloadMissingResourceLimits reports whether any container or init container in src has no
// resources.limits at all (nil or empty map — Kubernetes has no per-resource "partial" distinction
// at this level, and neither does the mock's audit command).
func workloadMissingResourceLimits(src report.WorkloadSource) bool {
	for _, c := range src.Spec.Containers {
		if len(c.Resources.Limits) == 0 {
			return true
		}
	}
	for _, c := range src.Spec.InitContainers {
		if len(c.Resources.Limits) == 0 {
			return true
		}
	}
	return false
}
