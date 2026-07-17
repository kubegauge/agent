// psa.go implements the KG-PS-* checks (Pod Security Admission posture): namespaces missing the
// enforce label, privileged containers, hostPath volumes, and shared host namespaces
// (hostNetwork/hostPID/hostIPC). All pod-level checks scan snap.Pods directly (the actual running
// pods, cluster-wide) rather than controller pod templates, mirroring the mock's own audit
// commands (`kubectl get pods -A ...`).
//
// KG-PS-002 ("Namespaces críticos usam enforce=restricted") is left out: like KG-NP-002, it
// requires classifying which namespaces are "critical", a concept with no signal in a live
// cluster snapshot. Unlike KG-NP-002 — where dropping the criticality filter still yields a
// distinct, useful check (egress vs. ingress default-deny) — doing the same here would just
// re-test the same enforce label KG-PS-001 already reports on, with an arbitrarily stricter
// threshold ("restricted" instead of "any profile"). That's padding, not a new signal, so it's
// left out rather than invented.
package checks

import (
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// ---- KG-PS-001: namespaces missing the PSA enforce label ---------------------------------------

type psaEnforceLabelCheck struct{}

func (psaEnforceLabelCheck) ID() string { return "KG-PS-001" }

// Run flags every non-system namespace missing the pod-security.kubernetes.io/enforce label.
// System namespaces are excluded: kube-system commonly runs components that would violate
// baseline/restricted (e.g. some CNI/node agents), and cluster distributions rarely label it
// themselves.
func (psaEnforceLabelCheck) Run(snap *snapshot.Snapshot) Result {
	var missing []string
	for _, ns := range snap.Namespaces {
		if isSystemNamespace(ns.Name) {
			continue
		}
		if _, ok := ns.Labels["pod-security.kubernetes.io/enforce"]; !ok {
			missing = append(missing, ns.Name)
		}
	}
	return namespaceResult(missing, "fail")
}

// ---- KG-PS-003: privileged containers outside kube-system --------------------------------------

type privilegedPodCheck struct{}

func (privilegedPodCheck) ID() string { return "KG-PS-003" }

// Run flags pods (outside system namespaces) with any container or init container running
// privileged: true. privileged disables nearly all container isolation, so any hit here is a
// hard fail.
func (privilegedPodCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, p := range snap.Pods {
		if isSystemNamespace(p.Namespace) {
			continue
		}
		if podHasPrivilegedContainer(p) {
			resources = append(resources, "pod/"+p.Namespace+"/"+p.Name)
			nsSet[p.Namespace] = true
		}
	}
	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: "fail", Namespaces: sortedKeys(nsSet), AffectedResources: resources}
}

func podHasPrivilegedContainer(p corev1.Pod) bool {
	for _, c := range p.Spec.Containers {
		if isPrivileged(c.SecurityContext) {
			return true
		}
	}
	for _, c := range p.Spec.InitContainers {
		if isPrivileged(c.SecurityContext) {
			return true
		}
	}
	return false
}

func isPrivileged(sc *corev1.SecurityContext) bool {
	return sc != nil && sc.Privileged != nil && *sc.Privileged
}

// ---- KG-PS-004: hostNetwork/hostPID/hostIPC outside kube-system ---------------------------------

type hostNamespacesCheck struct{}

func (hostNamespacesCheck) ID() string { return "KG-PS-004" }

// Run flags pods (outside system namespaces) sharing a host namespace: hostNetwork, hostPID or
// hostIPC. kube-system legitimately runs kube-proxy/CNI/node-agent pods that need these; PSS
// baseline prohibits them everywhere else, and — unlike hostPath below — there's no common
// legitimate exception in an application namespace, so any hit outside kube-system is a hard
// fail.
func (hostNamespacesCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, p := range snap.Pods {
		if isSystemNamespace(p.Namespace) {
			continue
		}
		if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
			resources = append(resources, "pod/"+p.Namespace+"/"+p.Name)
			nsSet[p.Namespace] = true
		}
	}
	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: "fail", Namespaces: sortedKeys(nsSet), AffectedResources: resources}
}

// ---- KG-PS-005: hostPath volumes outside kube-system --------------------------------------------

type hostPathVolumeCheck struct{}

func (hostPathVolumeCheck) ID() string { return "KG-PS-005" }

// Run flags pods (outside system namespaces) with a hostPath volume as a warn, not a fail: the
// mock's own explanation calls out legitimate log/metrics agent exceptions that need case-by-case
// review rather than an automatic hard failure.
func (hostPathVolumeCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, p := range snap.Pods {
		if isSystemNamespace(p.Namespace) {
			continue
		}
		if podHasHostPathVolume(p) {
			resources = append(resources, "pod/"+p.Namespace+"/"+p.Name)
			nsSet[p.Namespace] = true
		}
	}
	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: "warn", Namespaces: sortedKeys(nsSet), AffectedResources: resources}
}

func podHasHostPathVolume(p corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}
