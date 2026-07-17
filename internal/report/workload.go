// workload.go builds WorkloadPosture entries (one per Deployment/StatefulSet/DaemonSet pod
// template, plus every ownerReferences-less Pod) via a worst-of-containers aggregation.
//
// psaLevel below is a SIMPLIFIED evaluator, not the real Pod Security Admission algorithm: it
// only looks at the handful of signals the B5 spec calls out (privileged containers, host
// namespaces, hostPath volumes, explicit Unconfined seccomp for "privileged"; runAsNonRoot +
// no privilege escalation + capabilities dropped + a decent seccomp profile for "restricted").
// A full PSA-equivalent evaluator (all baseline/restricted controls) remains out of scope: M3
// (internal/checks/secctx.go, runtime.go, secrets.go, supplychain.go — KG-SC-*/KG-RT-*/KG-SE-*/
// KG-SU-*) reuses this file's worst-of aggregation as-is (via the exported BuildWorkloads/
// WorkloadSources below) rather than extending psaLevel itself.
package report

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// WorkloadSource is the common shape needed to inspect a workload's pod template, regardless of
// whether it came from a Deployment/StatefulSet/DaemonSet pod template or a standalone Pod.
// Exported (M3) so internal/checks can reuse the exact same "what counts as a workload" source
// list (WorkloadSources below) instead of re-deriving it: KG-SC-005 (resource limits), KG-RT-004
// (seLinuxOptions), KG-SE-002 (secrets via env) and KG-SU-* (image hygiene) all need raw container
// data — resources.limits, seLinuxOptions, env/envFrom, container images — that WorkloadPosture's
// worst-of aggregation deliberately does not keep. podLike below is kept as an alias so this file's
// pre-existing code (aggregatePosture, the literals in workload_test.go) needs no further changes.
type WorkloadSource struct {
	Name      string
	Namespace string
	Kind      string
	Spec      corev1.PodSpec
	// Labels are the POD labels (template labels for controllers, object labels for bare Pods) —
	// what Service selectors and NetworkPolicy podSelectors match against (M5: BuildNetwork).
	Labels      map[string]string
	Annotations map[string]string
}

// podLike is an alias of WorkloadSource: this file's pre-M3 code refers to it by its original,
// unexported name and lowercase field names via the struct literals below.
type podLike = WorkloadSource

// WorkloadSources returns every Deployment/StatefulSet/DaemonSet pod template and every
// ownerReferences-less Pod in the snapshot (B5's workload selection rule). Exported (M3) — see
// WorkloadSource's doc comment. BuildWorkloads below is just WorkloadSources + aggregatePosture.
func WorkloadSources(snap *snapshot.Snapshot) []WorkloadSource {
	sources := make([]WorkloadSource, 0, len(snap.Deployments)+len(snap.StatefulSets)+len(snap.DaemonSets)+len(snap.Pods))

	for _, d := range snap.Deployments {
		sources = append(sources, WorkloadSource{
			Name: d.Name, Namespace: d.Namespace, Kind: "Deployment",
			Spec: d.Spec.Template.Spec, Labels: d.Spec.Template.Labels, Annotations: d.Spec.Template.Annotations,
		})
	}
	for _, s := range snap.StatefulSets {
		sources = append(sources, WorkloadSource{
			Name: s.Name, Namespace: s.Namespace, Kind: "StatefulSet",
			Spec: s.Spec.Template.Spec, Labels: s.Spec.Template.Labels, Annotations: s.Spec.Template.Annotations,
		})
	}
	for _, ds := range snap.DaemonSets {
		sources = append(sources, WorkloadSource{
			Name: ds.Name, Namespace: ds.Namespace, Kind: "DaemonSet",
			Spec: ds.Spec.Template.Spec, Labels: ds.Spec.Template.Labels, Annotations: ds.Spec.Template.Annotations,
		})
	}
	for _, p := range snap.Pods {
		if len(p.OwnerReferences) == 0 {
			sources = append(sources, WorkloadSource{
				Name: p.Name, Namespace: p.Namespace, Kind: "Pod",
				Spec: p.Spec, Labels: p.Labels, Annotations: p.Annotations,
			})
		}
	}
	return sources
}

// BuildWorkloads assembles a WorkloadPosture for every Deployment, StatefulSet, DaemonSet (from
// their pod template) and every Pod without ownerReferences (B5). Exported (renamed from
// buildWorkloads in M3) so internal/checks's KG-SC-*/KG-RT-* checks can reuse this exact worst-of-
// containers aggregation instead of duplicating it — see WorkloadSource's doc comment.
func BuildWorkloads(snap *snapshot.Snapshot) []WorkloadPosture {
	saAutomount := serviceAccountAutomountIndex(snap.ServiceAccounts)
	sources := WorkloadSources(snap)

	result := make([]WorkloadPosture, 0, len(sources))
	for _, src := range sources {
		result = append(result, aggregatePosture(src, saAutomount))
	}
	return result
}

// serviceAccountAutomountIndex maps "namespace/name" -> ServiceAccount.AutomountServiceAccountToken.
func serviceAccountAutomountIndex(accounts []corev1.ServiceAccount) map[string]*bool {
	idx := make(map[string]*bool, len(accounts))
	for i := range accounts {
		sa := &accounts[i]
		idx[sa.Namespace+"/"+sa.Name] = sa.AutomountServiceAccountToken
	}
	return idx
}

// aggregatePosture applies the B5 worst-of-containers table to a single pod template/pod.
func aggregatePosture(src podLike, saAutomount map[string]*bool) WorkloadPosture {
	containers := src.Spec.Containers
	podSC := src.Spec.SecurityContext

	runAsNonRoot := len(containers) > 0 // AND across containers; vacuously false with none
	readOnlyRootFilesystem := len(containers) > 0
	capabilitiesDropAll := len(containers) > 0
	allowPrivilegeEscalation := false // OR across containers; default true is applied per-container below
	anyPrivileged := false

	worstSeccomp := -1
	worstAppArmor := -1

	for _, c := range containers {
		cSC := c.SecurityContext

		if !effectiveRunAsNonRoot(cSC, podSC) {
			runAsNonRoot = false
		}
		if !effectiveReadOnlyRootFS(cSC) {
			readOnlyRootFilesystem = false
		}
		if effectiveAllowPrivilegeEscalation(cSC) {
			allowPrivilegeEscalation = true
		}
		if !effectiveCapabilitiesDropAll(cSC) {
			capabilitiesDropAll = false
		}
		if cSC != nil && cSC.Privileged != nil && *cSC.Privileged {
			anyPrivileged = true
		}

		if rank := seccompRank(effectiveSeccomp(cSC, podSC)); rank > worstSeccomp {
			worstSeccomp = rank
		}
		if rank := appArmorRank(effectiveAppArmor(c.Name, cSC, podSC, src.Annotations)); rank > worstAppArmor {
			worstAppArmor = rank
		}
	}

	if worstSeccomp == -1 {
		worstSeccomp = seccompRank("none")
	}
	if worstAppArmor == -1 {
		worstAppArmor = appArmorRank("none")
	}
	seccompProfile := seccompRankToString(worstSeccomp)
	appArmorProfile := appArmorRankToString(worstAppArmor)

	hostNetwork := src.Spec.HostNetwork
	hostPID := src.Spec.HostPID
	hostIPC := src.Spec.HostIPC
	hasHostPathVolume := hasHostPath(src.Spec.Volumes)

	automount := effectiveAutomount(src, saAutomount)

	psaLevel := "baseline"
	violatesBaseline := anyPrivileged || hostNetwork || hostPID || hostIPC || hasHostPathVolume || seccompProfile == "Unconfined"
	switch {
	case violatesBaseline:
		psaLevel = "privileged"
	case runAsNonRoot && !allowPrivilegeEscalation && capabilitiesDropAll && (seccompProfile == "RuntimeDefault" || seccompProfile == "Localhost"):
		psaLevel = "restricted"
	}

	return WorkloadPosture{
		Name:                         src.Name,
		Namespace:                    src.Namespace,
		Kind:                         src.Kind,
		PsaLevel:                     psaLevel,
		RunAsNonRoot:                 runAsNonRoot,
		ReadOnlyRootFilesystem:       readOnlyRootFilesystem,
		AllowPrivilegeEscalation:     allowPrivilegeEscalation,
		CapabilitiesDropAll:          capabilitiesDropAll,
		SeccompProfile:               seccompProfile,
		AppArmorProfile:              appArmorProfile,
		AutomountServiceAccountToken: automount,
		HostNetwork:                  hostNetwork,
	}
}

// effectiveRunAsNonRoot: container-level overrides pod-level; absent -> false (B5 default).
func effectiveRunAsNonRoot(cSC *corev1.SecurityContext, podSC *corev1.PodSecurityContext) bool {
	if cSC != nil && cSC.RunAsNonRoot != nil {
		return *cSC.RunAsNonRoot
	}
	if podSC != nil && podSC.RunAsNonRoot != nil {
		return *podSC.RunAsNonRoot
	}
	return false
}

// effectiveReadOnlyRootFS: container-only field (PodSecurityContext has no equivalent); absent -> false.
func effectiveReadOnlyRootFS(cSC *corev1.SecurityContext) bool {
	if cSC != nil && cSC.ReadOnlyRootFilesystem != nil {
		return *cSC.ReadOnlyRootFilesystem
	}
	return false
}

// effectiveAllowPrivilegeEscalation: container-only field; absent -> true (K8s default, B5).
func effectiveAllowPrivilegeEscalation(cSC *corev1.SecurityContext) bool {
	if cSC != nil && cSC.AllowPrivilegeEscalation != nil {
		return *cSC.AllowPrivilegeEscalation
	}
	return true
}

// effectiveCapabilitiesDropAll: container-only field; true only if capabilities.drop contains "ALL".
func effectiveCapabilitiesDropAll(cSC *corev1.SecurityContext) bool {
	if cSC == nil || cSC.Capabilities == nil {
		return false
	}
	for _, capability := range cSC.Capabilities.Drop {
		if capability == "ALL" {
			return true
		}
	}
	return false
}

// effectiveSeccomp resolves the effective seccomp profile type string for a container:
// container-level overrides pod-level; absent -> "none" (B5).
func effectiveSeccomp(cSC *corev1.SecurityContext, podSC *corev1.PodSecurityContext) string {
	if cSC != nil && cSC.SeccompProfile != nil {
		return string(cSC.SeccompProfile.Type)
	}
	if podSC != nil && podSC.SeccompProfile != nil {
		return string(podSC.SeccompProfile.Type)
	}
	return "none"
}

// seccompRank orders seccomp profiles worst-to-best as Unconfined > none > Localhost > RuntimeDefault
// (B5); higher rank = worse. Aggregation reports the worst rank seen across containers.
func seccompRank(profile string) int {
	switch profile {
	case "Unconfined":
		return 3
	case "none":
		return 2
	case "Localhost":
		return 1
	case "RuntimeDefault":
		return 0
	default:
		return 2
	}
}

func seccompRankToString(rank int) string {
	switch rank {
	case 3:
		return "Unconfined"
	case 1:
		return "Localhost"
	case 0:
		return "RuntimeDefault"
	default:
		return "none"
	}
}

// effectiveAppArmor resolves the effective AppArmor profile for a container: the structured
// securityContext.appArmorProfile field (container overrides pod, K8s >= 1.30) takes precedence
// over the legacy container.apparmor.security.beta.kubernetes.io/<container> annotation; absent -> "none".
func effectiveAppArmor(containerName string, cSC *corev1.SecurityContext, podSC *corev1.PodSecurityContext, annotations map[string]string) string {
	if cSC != nil && cSC.AppArmorProfile != nil {
		return mapAppArmorProfileType(cSC.AppArmorProfile.Type)
	}
	if podSC != nil && podSC.AppArmorProfile != nil {
		return mapAppArmorProfileType(podSC.AppArmorProfile.Type)
	}
	if annotations != nil {
		if v, ok := annotations["container.apparmor.security.beta.kubernetes.io/"+containerName]; ok {
			return mapLegacyAppArmorAnnotation(v)
		}
	}
	return "none"
}

func mapAppArmorProfileType(t corev1.AppArmorProfileType) string {
	switch t {
	case corev1.AppArmorProfileTypeRuntimeDefault:
		return "runtime/default"
	case corev1.AppArmorProfileTypeLocalhost:
		return "localhost"
	case corev1.AppArmorProfileTypeUnconfined:
		return "unconfined"
	default:
		return "none"
	}
}

// mapLegacyAppArmorAnnotation parses the legacy annotation value format: "runtime/default",
// "localhost/<profile-name>", or "unconfined".
func mapLegacyAppArmorAnnotation(v string) string {
	switch {
	case v == "unconfined":
		return "unconfined"
	case v == "runtime/default":
		return "runtime/default"
	case len(v) >= len("localhost/") && v[:len("localhost/")] == "localhost/":
		return "localhost"
	default:
		return "none"
	}
}

// appArmorRank mirrors seccompRank's worst-to-best ordering: unconfined > none > localhost > runtime/default.
func appArmorRank(profile string) int {
	switch profile {
	case "unconfined":
		return 3
	case "none":
		return 2
	case "localhost":
		return 1
	case "runtime/default":
		return 0
	default:
		return 2
	}
}

func appArmorRankToString(rank int) string {
	switch rank {
	case 3:
		return "unconfined"
	case 1:
		return "localhost"
	case 0:
		return "runtime/default"
	default:
		return "none"
	}
}

func hasHostPath(volumes []corev1.Volume) bool {
	for _, v := range volumes {
		if v.HostPath != nil {
			return true
		}
	}
	return false
}

// effectiveAutomount: pod.Spec.AutomountServiceAccountToken if set; else the ServiceAccount's
// field; else true (B5 default). An unset ServiceAccountName defaults to "default" (K8s behavior).
func effectiveAutomount(src podLike, saAutomount map[string]*bool) bool {
	if src.Spec.AutomountServiceAccountToken != nil {
		return *src.Spec.AutomountServiceAccountToken
	}

	saName := src.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	if v, ok := saAutomount[src.Namespace+"/"+saName]; ok && v != nil {
		return *v
	}
	return true
}
