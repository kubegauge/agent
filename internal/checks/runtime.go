// runtime.go implements the KG-RT-* checks (runtime confinement profiles): seccomp RuntimeDefault,
// AppArmor runtime/default, explicit Unconfined (seccomp or AppArmor) as an antipattern, and
// SELinux seLinuxOptions.user/role customization.
//
// KG-RT-001/002/003 reuse report.BuildWorkloads's worst-of-containers SeccompProfile/AppArmorProfile
// strings (report/workload.go already resolves pod-vs-container precedence and the legacy AppArmor
// annotation for us — recomputing that here would duplicate it). KG-RT-004 needs the raw
// seLinuxOptions struct (not carried by WorkloadPosture at all), so it uses report.WorkloadSources
// and inspects pod- and container-level SecurityContext directly.
//
// All four checks exclude system namespaces, consistent with every M2/M3 pod-level check (see
// psa.go, secctx.go).
//
// All four mock ids (KG-RT-001..004) turned out to be computable; none were left out.
package checks

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// ---- KG-RT-001: seccomp RuntimeDefault ----------------------------------------------------------

type seccompRuntimeDefaultCheck struct{}

func (seccompRuntimeDefaultCheck) ID() string { return "KG-RT-001" }

// Run flags every workload (outside system namespaces) whose worst-of-containers seccomp profile
// is anything other than exactly "RuntimeDefault" — mirroring the mock's own audit command
// (`!= "RuntimeDefault"`) verbatim. Note this also flags a custom "Localhost" profile: a
// custom-but-confined profile is arguably at least as good as RuntimeDefault, but the mock's own
// seeded auditCommand does not carve out that exception, so we match it rather than invent a
// looser rule the catalog text doesn't describe.
func (seccompRuntimeDefaultCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, w := range report.BuildWorkloads(snap) {
		if isSystemNamespace(w.Namespace) {
			continue
		}
		if w.SeccompProfile != "RuntimeDefault" {
			resources = append(resources, workloadResourceRef(w.Kind, w.Namespace, w.Name))
			nsSet[w.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "fail")
}

// ---- KG-RT-002: AppArmor runtime/default --------------------------------------------------------

type appArmorRuntimeDefaultCheck struct{}

func (appArmorRuntimeDefaultCheck) ID() string { return "KG-RT-002" }

// Run flags every workload (outside system namespaces) whose worst-of-containers AppArmor profile
// is anything other than "runtime/default", as a warn rather than a fail: AppArmor only exists on
// nodes whose kernel has it enabled (Ubuntu/Debian) — the mock's own explanation says exactly this
// ("Check whether the node kernel has AppArmor") — so a finding here is a real but
// environment-dependent signal, not an unconditional hard failure.
func (appArmorRuntimeDefaultCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, w := range report.BuildWorkloads(snap) {
		if isSystemNamespace(w.Namespace) {
			continue
		}
		if w.AppArmorProfile != "runtime/default" {
			resources = append(resources, workloadResourceRef(w.Kind, w.Namespace, w.Name))
			nsSet[w.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "warn")
}

// ---- KG-RT-003: no explicit Unconfined ----------------------------------------------------------

type noUnconfinedProfileCheck struct{}

func (noUnconfinedProfileCheck) ID() string { return "KG-RT-003" }

// Run flags every workload (outside system namespaces) that explicitly sets seccomp or AppArmor to
// Unconfined on any container. Deterministic fail, higher-severity than merely missing a profile
// (KG-RT-001/002): explicitly opting OUT of confinement the runtime would otherwise apply by
// default is a deliberate weakening, not just an absent hardening step — matching the mock's own
// framing: setting Unconfined explicitly is WORSE than setting nothing at all.
func (noUnconfinedProfileCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, w := range report.BuildWorkloads(snap) {
		if isSystemNamespace(w.Namespace) {
			continue
		}
		if w.SeccompProfile == "Unconfined" || w.AppArmorProfile == "unconfined" {
			resources = append(resources, workloadResourceRef(w.Kind, w.Namespace, w.Name))
			nsSet[w.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "fail")
}

// ---- KG-RT-004: SELinux seLinuxOptions.user/role ------------------------------------------------

type seLinuxOptionsCheck struct{}

func (seLinuxOptionsCheck) ID() string { return "KG-RT-004" }

// Run inspects every workload (outside system namespaces) for a customized seLinuxOptions.user or
// .role, at pod level or on any container/init container (container-level would override pod-level
// per Kubernetes semantics, so both are checked — a deliberate widening versus the mock's own
// audit command, which only inspects the pod-level field; narrowing to just that would silently
// miss a container-level override). PSS baseline permits seLinuxOptions.type/level but prohibits
// customizing user/role, so only those two fields are checked (not mere presence of the struct).
//
// Status mirrors netpol.go's cniSupportCheck 3-way pattern rather than a binary pass/fail: "info"
// when nothing is found at all (this cluster may simply not run SELinux-enforcing nodes — the mock
// itself notes its own demo cluster is Ubuntu/AppArmor, where this simply does not apply; we
// cannot tell either way from the snapshot alone), "warn" when a customization is found (a real
// signal, but with legitimate RHEL/CentOS exceptions that need case-by-case review) — never a false
// "fail", since we can't confirm the node even enforces SELinux.
func (seLinuxOptionsCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, src := range report.WorkloadSources(snap) {
		if isSystemNamespace(src.Namespace) {
			continue
		}
		if workloadHasCustomSELinux(src) {
			resources = append(resources, workloadResourceRef(src.Kind, src.Namespace, src.Name))
			nsSet[src.Namespace] = true
		}
	}
	if len(resources) == 0 {
		return Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}}
	}
	return workloadSetResult(resources, nsSet, "warn")
}

func workloadHasCustomSELinux(src report.WorkloadSource) bool {
	if src.Spec.SecurityContext != nil && hasCustomSELinuxUserOrRole(src.Spec.SecurityContext.SELinuxOptions) {
		return true
	}
	for _, c := range src.Spec.Containers {
		if c.SecurityContext != nil && hasCustomSELinuxUserOrRole(c.SecurityContext.SELinuxOptions) {
			return true
		}
	}
	for _, c := range src.Spec.InitContainers {
		if c.SecurityContext != nil && hasCustomSELinuxUserOrRole(c.SecurityContext.SELinuxOptions) {
			return true
		}
	}
	return false
}

func hasCustomSELinuxUserOrRole(opts *corev1.SELinuxOptions) bool {
	return opts != nil && (opts.User != "" || opts.Role != "")
}
