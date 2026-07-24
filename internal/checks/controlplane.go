// controlplane.go implements the KG-CP-* checks (Control Plane / CIS, M4) plus KG-SE-001
// (Encryption at rest — see secrets.go's doc comment for why it lives here instead), by locating
// kube-system's control-plane static pods (kube-apiserver-*/etcd-*, by name prefix and/or the
// component= label kubeadm sets on them) and parsing CLI flags directly out of their container
// Command/Args — the only place this information exists as a Kubernetes API object: kube-apiserver
// and etcd don't expose their own flags via any resource this snapshot lists, and a static pod's
// spec (unlike, say, a Deployment's) IS its actual running configuration — there's no separate
// "desired state" for it to diverge from.
//
// PLAN-FASE-2.md §6's KG-CP-* row additionally mentions --authorization-mode and --profiling as
// "typical" flags, but originally neither corresponded to its own mock id: client/src/data/
// checks.ts's control-plane category (the actual seed of truth for this milestone, per its own
// brief) defined exactly six ids, none titled around authorization-mode or profiling. Implementing
// a flag with no backing catalog id would have no Entry to attach it to and no way to surface it
// in the UI, so this file originally implemented exactly the six ids that existed. The KCSA/CIS
// hardening alignment then extended the catalog itself — KG-CP-007/008 on 2026-07-13, and
// KG-CP-009..012 in the follow-up batch (which is what finally gave authorization-mode and
// profiling their own ids) — so all of these DO have backing entries:
//
//   - KG-CP-001 (--anonymous-auth=false), KG-CP-002 (--audit-log-path set), KG-CP-006
//     (--enable-admission-plugins contains NodeRestriction), KG-CP-007 (--enable-admission-plugins
//     contains AlwaysPullImages, warn), KG-CP-008 (--disable-admission-plugins must NOT contain
//     PodSecurity), KG-CP-009 (--audit-policy-file + retention flags), KG-CP-010
//     (--authorization-mode with Node,RBAC and never AlwaysAllow) and KG-CP-012 (OIDC/external IdP,
//     warn): all read from the kube-apiserver static pod.
//   - KG-CP-011 (--profiling=false) reads apiserver, scheduler AND controller-manager static pods
//     — the one multi-component check here; see its Run's doc comment.
//   - KG-CP-003 (etcd --client-cert-auth=true AND --peer-client-cert-auth=true, per the mock's own
//     title "etcd com client-cert-auth e peer TLS"): reads the etcd static pod.
//   - KG-CP-004 ("Kubelet: --authorization-mode=Webhook e anonymous off") and KG-CP-005 ("Kubelet:
//     --read-only-port=0") are left out: both audit the KUBELET's own config, which lives in a file
//     on the node's filesystem (/var/lib/kubelet/config.yaml, per the mock's own auditCommand for
//     both ids) — not any object the Kubernetes API exposes, so no get/list snapshot can ever see
//     it, on any distribution. Their catalog entries are kept (catalog.yaml) exactly like
//     KG-RB-004/005 and KG-PS-002 (see rbac.go/psa.go) so the mock ids stay documented even without
//     a Check.
//
// Managed-cluster degradation: EKS/GKE/AKS (whose control planes are never exposed as static pods,
// by the provider's own design) and any cluster where the API server itself isn't visible as a
// static pod hide the control plane entirely, so every check below reports "na" (not applicable)
// rather than guessing pass/fail from nothing — on managed clusters the control plane is invisible.
// See isManagedControlPlane's doc comment for exactly which signal decides this and why, and
// controlPlaneFlagResult's for the narrower, additional fallback this file layers on top of it.
package checks

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// apiserverNamePrefix/apiserverComponent and etcdNamePrefix/etcdComponent are the two
// (name-prefix, component-label) pairs this file's checks need. controlPlanePods below matches on
// EITHER signal: kubeadm always sets both, but matching on just one tolerates any tool/distro that
// only sets one of them. The same helper would just as readily locate a
// kube-controller-manager-*/component=kube-controller-manager static pod — no KG-CP-* id needs a
// controller-manager flag today (see the package doc comment above), so nothing calls it with that
// pair, but the mechanism carries over unchanged the day a future id needs it.
const (
	apiserverNamePrefix         = "kube-apiserver-"
	apiserverComponent          = "kube-apiserver"
	etcdNamePrefix              = "etcd-"
	etcdComponent               = "etcd"
	schedulerNamePrefix         = "kube-scheduler-"
	schedulerComponent          = "kube-scheduler"
	controllerManagerNamePrefix = "kube-controller-manager-"
	controllerManagerComponent  = "kube-controller-manager"
)

// controlPlanePods returns every kube-system Pod recognized as component's static pod: its name
// has namePrefix (kubeadm's own convention, e.g. "kube-apiserver-<node>") or it carries the label
// component=<component> (also kubeadm's convention, and a more robust signal across manifest/
// node-name variations). A cluster with multiple control-plane nodes (HA) can return more than one
// pod; callers evaluate each independently rather than assuming a single instance.
func controlPlanePods(snap *snapshot.Snapshot, namePrefix, component string) []corev1.Pod {
	var out []corev1.Pod
	for _, p := range snap.Pods {
		if p.Namespace != "kube-system" {
			continue
		}
		if strings.HasPrefix(p.Name, namePrefix) || p.Labels["component"] == component {
			out = append(out, p)
		}
	}
	return out
}

// detectedDistribution re-derives the same B5 heuristic report.DetectDistribution (cluster.go)
// uses when assembling wire.KubernetesInfo, from the fields already available on Snapshot. That
// finished distribution string only otherwise exists on wire.KubernetesInfo (built later, in
// wire.Build) — not on Snapshot itself — so isManagedControlPlane recomputes it directly here: a
// pure function of data this package already imports report for (rbac.go's RbacFinding uses
// report.RbacFinding), so this isn't a new dependency.
func detectedDistribution(snap *snapshot.Snapshot) string {
	gitVersion := ""
	if snap.ServerVersion != nil {
		gitVersion = snap.ServerVersion.GitVersion
	}
	return report.DetectDistribution(snap.Nodes, gitVersion, snap.KubeadmConfigMapFound)
}

// isManagedControlPlane decides whether this snapshot's control plane can be introspected at all.
// Per this milestone's brief, that's a single shared signal for every check in this file: managed
// when the detected distribution is eks/gke/aks (their control planes are never exposed as static
// pods in kube-system — there is nothing to find there, ever, by the provider's own design) OR when
// no kube-apiserver static pod is present regardless of distribution (covers "unknown"/misdetected
// clusters the same way). Deliberately NOT a separate signal per component/check: the brief keys
// the whole degradation off apiserver visibility alone, treating it as a proxy for "is this a
// self-hosted control plane we can see into at all" rather than asking that question once per
// static pod. See controlPlaneFlagResult for the one additional, narrower fallback layered on top:
// a specific check's own component (e.g. etcd) still being absent even though the apiserver,
// specifically, is present.
func isManagedControlPlane(snap *snapshot.Snapshot) bool {
	switch detectedDistribution(snap) {
	case "eks", "gke", "aks":
		return true
	}
	return len(controlPlanePods(snap, apiserverNamePrefix, apiserverComponent)) == 0
}

// parseFlags extracts CLI flags from a static pod container's Command and Args, concatenated in
// that order (kubeadm's generated manifests put the full "binary + all flags" argv under Command
// with Args empty, but a manifest that instead puts flags under Args — or splits across both — is
// handled identically). Both flag forms this milestone requires are supported: "--flag=value" and
// the space-separated "--flag value" (two tokens). The very first token (the binary name, e.g.
// "kube-apiserver") never starts with "--" and is simply skipped, same as any other non-flag
// token. A flag with nothing after it — either it's the last token, or the next token is itself
// another "--flag" — is recorded with value "true", the conventional meaning of a bare boolean CLI
// flag's presence; none of this file's checks currently rely on that case (every flag they read is
// always written with an explicit value by kubeadm), but it keeps the parser correct rather than
// silently dropping such a flag.
func parseFlags(command, args []string) map[string]string {
	tokens := make([]string, 0, len(command)+len(args))
	tokens = append(tokens, command...)
	tokens = append(tokens, args...)

	flags := map[string]string{}
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if !strings.HasPrefix(tok, "--") {
			continue
		}
		name := strings.TrimPrefix(tok, "--")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			flags[name[:eq]] = name[eq+1:]
			continue
		}
		if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "--") {
			flags[name] = tokens[i+1]
			i++
			continue
		}
		flags[name] = "true"
	}
	return flags
}

// staticPodFlags merges parseFlags across every container in a static pod (kubeadm's static pods
// carry exactly one container, but merging here is defensive rather than indexing
// p.Spec.Containers[0] and assuming that).
func staticPodFlags(p corev1.Pod) map[string]string {
	flags := map[string]string{}
	for _, c := range p.Spec.Containers {
		for k, v := range parseFlags(c.Command, c.Args) {
			flags[k] = v
		}
	}
	return flags
}

// commaListContains reports whether entry appears as one of the comma-separated entries in a flag
// value like --enable-admission-plugins or --authorization-mode (an exact match per entry, not a
// substring search of the whole string — so e.g. a hypothetical "NodeRestrictionExtra" plugin name
// wouldn't false-match a search for "NodeRestriction"). Named generically since KG-CP-010: the same
// comma-list convention covers admission plugins AND authorization modes.
func commaListContains(value, entry string) bool {
	for _, p := range strings.Split(value, ",") {
		if strings.TrimSpace(p) == entry {
			return true
		}
	}
	return false
}

// controlPlaneFlagResult is the shared evaluation shape for every check in this file:
//
//  1. degrade to "na" (not applicable) on a managed control plane (isManagedControlPlane) — the
//     gate this behavior specifies, shared identically by every check below;
//  2. degrade to "info" too if THIS check's own component simply has no static pod in the
//     snapshot at all. This is a narrower fallback ADDED on top of (1), which is keyed on the
//     apiserver alone: without it, KG-CP-003 (etcd) would silently report a false "pass" against,
//     say, an external etcd cluster that was never a kube-system static pod, on an otherwise
//     self-hosted (apiserver-visible, so not caught by (1)) control plane. Reporting "no evidence"
//     as info rather than an unearned "pass" is the same instinct as cniSupportCheck's info branch
//     (netpol.go) when no recognized CNI DaemonSet is found;
//  3. otherwise, evaluate compliant against every matching pod (HA control planes can have more
//     than one) and fail/warn (status) listing every pod that doesn't satisfy it, "pass" if every
//     one does.
//
// status is a parameter (not hardcoded "fail") purely for symmetry with hostPathVolumeCheck
// (psa.go), which does the same thing for "warn" — every check below in this file in fact passes
// "fail".
func controlPlaneFlagResult(snap *snapshot.Snapshot, namePrefix, component, status string, compliant func(flags map[string]string) bool) Result {
	if isManagedControlPlane(snap) {
		return Result{Status: "na", Namespaces: []string{}, AffectedResources: []string{}}
	}

	pods := controlPlanePods(snap, namePrefix, component)
	if len(pods) == 0 {
		return Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}}
	}

	var offending []string
	for _, p := range pods {
		if !compliant(staticPodFlags(p)) {
			offending = append(offending, p.Name)
		}
	}
	if len(offending) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	return Result{Status: status, Namespaces: []string{}, AffectedResources: prefixedSorted("pod/kube-system/", offending)}
}

// ---- KG-CP-001: kube-apiserver --anonymous-auth=false ------------------------------------------

type apiserverAnonymousAuthCheck struct{}

func (apiserverAnonymousAuthCheck) ID() string { return "KG-CP-001" }

// Run requires --anonymous-auth=false explicitly: the flag's own Kubernetes default is true
// (deprecated but still the documented default), so an absent flag is exactly as non-compliant as
// an explicit --anonymous-auth=true — this check never treats "unset" as "presumably fine".
func (apiserverAnonymousAuthCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "fail", func(flags map[string]string) bool {
		return flags["anonymous-auth"] == "false"
	})
}

// ---- KG-CP-002: kube-apiserver --audit-log-path set ---------------------------------------------

type auditLogPathCheck struct{}

func (auditLogPathCheck) ID() string { return "KG-CP-002" }

// Run requires a non-empty --audit-log-path, mirroring the mock's own auditCommand (a grep for
// that one flag). --audit-policy-file is discussed in the explanation/remediation text but isn't
// what the mock's auditCommand actually checks, so this doesn't require it either.
func (auditLogPathCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "fail", func(flags map[string]string) bool {
		v, ok := flags["audit-log-path"]
		return ok && v != ""
	})
}

// ---- KG-CP-003: etcd --client-cert-auth=true and --peer-client-cert-auth=true -------------------

type etcdClientCertAuthCheck struct{}

func (etcdClientCertAuthCheck) ID() string { return "KG-CP-003" }

// Run requires BOTH flags true, matching the check's own title ("etcd com client-cert-auth e peer
// TLS") and explanation (CIS 2.x: --client-cert-auth=true, --peer-client-cert-auth=true).
func (etcdClientCertAuthCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, etcdNamePrefix, etcdComponent, "fail", func(flags map[string]string) bool {
		return flags["client-cert-auth"] == "true" && flags["peer-client-cert-auth"] == "true"
	})
}

// ---- KG-CP-006: kube-apiserver --enable-admission-plugins contains NodeRestriction --------------

type nodeRestrictionAdmissionCheck struct{}

func (nodeRestrictionAdmissionCheck) ID() string { return "KG-CP-006" }

func (nodeRestrictionAdmissionCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "fail", func(flags map[string]string) bool {
		return commaListContains(flags["enable-admission-plugins"], "NodeRestriction")
	})
}

// ---- KG-CP-007: kube-apiserver --enable-admission-plugins contains AlwaysPullImages -------------

type alwaysPullImagesAdmissionCheck struct{}

func (alwaysPullImagesAdmissionCheck) ID() string { return "KG-CP-007" }

// Run reports "warn" (not "fail") when AlwaysPullImages is absent: CIS recommends the plugin
// (forcing imagePullPolicy Always, so a pod can never reuse another tenant's cached image without
// presenting registry credentials), but its operational cost is real — every pod restart depends
// on the registry being reachable — and the benefit is debated outside multi-tenant nodes. An
// audit signal rather than a hard fail, the same rationale as KG-RB-003/004.
func (alwaysPullImagesAdmissionCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "warn", func(flags map[string]string) bool {
		return commaListContains(flags["enable-admission-plugins"], "AlwaysPullImages")
	})
}

// ---- KG-CP-008: kube-apiserver --disable-admission-plugins must NOT contain PodSecurity ---------

type podSecurityNotDisabledCheck struct{}

func (podSecurityNotDisabledCheck) ID() string { return "KG-CP-008" }

// Run inverts the usual admission-plugin condition: PodSecurity is enabled BY DEFAULT since
// Kubernetes 1.25, so requiring it in --enable-admission-plugins (KG-CP-006 style) would
// false-fail perfectly healthy clusters that simply rely on the default. The only non-compliant
// state is disabling it explicitly via --disable-admission-plugins — which switches off PSA
// enforcement (everything KG-PS-* audits) for the entire cluster at once.
func (podSecurityNotDisabledCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "fail", func(flags map[string]string) bool {
		return !commaListContains(flags["disable-admission-plugins"], "PodSecurity")
	})
}

// ---- KG-CP-009: kube-apiserver audit policy + retention flags ------------------------------------

type auditPolicyAndRetentionCheck struct{}

func (auditPolicyAndRetentionCheck) ID() string { return "KG-CP-009" }

// Run requires --audit-policy-file AND all three retention flags (--audit-log-maxage/maxbackup/
// maxsize) non-empty, complementing KG-CP-002 (which only requires --audit-log-path, mirroring its
// mock's auditCommand — see auditLogPathCheck's doc comment): a path without a policy logs nothing
// useful, and a policy without retention grows unbounded until rotation deletes the evidence. CIS
// 1.2.16–1.2.19 recommend 30/10/100 as minimum values; this check requires presence, not those
// numeric thresholds, matching the presence-only granularity of every other flag check in this
// file (the catalog's remediation text carries the recommended values).
func (auditPolicyAndRetentionCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "fail", func(flags map[string]string) bool {
		for _, name := range []string{"audit-policy-file", "audit-log-maxage", "audit-log-maxbackup", "audit-log-maxsize"} {
			if v, ok := flags[name]; !ok || v == "" {
				return false
			}
		}
		return true
	})
}

// ---- KG-CP-010: kube-apiserver --authorization-mode includes Node,RBAC, never AlwaysAllow --------

type authorizationModeCheck struct{}

func (authorizationModeCheck) ID() string { return "KG-CP-010" }

// Run requires --authorization-mode to contain BOTH Node and RBAC (CIS 1.2.7/1.2.8) and to never
// contain AlwaysAllow (CIS 1.2.6). An absent flag fails outright: the apiserver's own default is
// AlwaysAllow — same "unset is exactly as non-compliant as the insecure value" stance as KG-CP-001.
// AlwaysAllow is rejected even alongside Node,RBAC because authorization modes are a first-match-
// allows chain: AlwaysAllow anywhere in the list approves every request before RBAC is consulted.
func (authorizationModeCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "fail", func(flags map[string]string) bool {
		modes, ok := flags["authorization-mode"]
		if !ok {
			return false
		}
		return commaListContains(modes, "Node") &&
			commaListContains(modes, "RBAC") &&
			!commaListContains(modes, "AlwaysAllow")
	})
}

// ---- KG-CP-011: --profiling=false on apiserver, scheduler and controller-manager ----------------

type profilingDisabledCheck struct{}

func (profilingDisabledCheck) ID() string { return "KG-CP-011" }

// Run requires --profiling=false explicitly on EVERY control-plane static pod found among
// apiserver, scheduler and controller-manager — the one check in this file spanning multiple
// components, because CIS states it once per component (1.2.15/1.3.2/1.4.1) with identical
// semantics: the flag's own default is true, exposing /debug/pprof (program state useful for both
// DoS and reconnaissance) on each component's serving port, so an absent flag fails exactly like
// an explicit true (KG-CP-001's stance). Components without a static pod in the snapshot are
// simply not evaluated — the apiserver's own presence is already guaranteed by the
// isManagedControlPlane gate, so there's never a "no pods at all" false pass here, and requiring
// scheduler/controller-manager visibility would false-fail self-hosted-but-not-kubeadm layouts.
func (profilingDisabledCheck) Run(snap *snapshot.Snapshot) Result {
	if isManagedControlPlane(snap) {
		return Result{Status: "na", Namespaces: []string{}, AffectedResources: []string{}}
	}

	var pods []corev1.Pod
	for _, pair := range [][2]string{
		{apiserverNamePrefix, apiserverComponent},
		{schedulerNamePrefix, schedulerComponent},
		{controllerManagerNamePrefix, controllerManagerComponent},
	} {
		pods = append(pods, controlPlanePods(snap, pair[0], pair[1])...)
	}

	var offending []string
	for _, p := range pods {
		if staticPodFlags(p)["profiling"] != "false" {
			offending = append(offending, p.Name)
		}
	}
	if len(offending) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	return Result{Status: "fail", Namespaces: []string{}, AffectedResources: prefixedSorted("pod/kube-system/", offending)}
}

// ---- KG-CP-012: kube-apiserver OIDC / external IdP configured ------------------------------------

type oidcAuthenticationCheck struct{}

func (oidcAuthenticationCheck) ID() string { return "KG-CP-012" }

// Run passes when the apiserver delegates user authentication to an external IdP: either the
// classic --oidc-issuer-url flag or --authentication-config (the structured
// AuthenticationConfiguration file that supersedes the oidc-* flags since K8s 1.30 — a cluster
// using it would false-warn if only the legacy flag were accepted). Absence is "warn", not "fail":
// client-certificate authn isn't insecure in itself, but certs can't be revoked before expiry and
// carry no MFA/lifecycle management — an external IdP is the maturity signal ISO A.5.16/A.8.5 ask
// about, same audit-not-enforcement rationale as KG-CP-007.
func (oidcAuthenticationCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "warn", func(flags map[string]string) bool {
		return flags["oidc-issuer-url"] != "" || flags["authentication-config"] != ""
	})
}

// ---- KG-SE-001: kube-apiserver --encryption-provider-config set (category stays "secrets") ------

type encryptionAtRestCheck struct{}

func (encryptionAtRestCheck) ID() string { return "KG-SE-001" }

// Run requires a non-empty --encryption-provider-config, matching the mock's own auditCommand (a
// grep for that flag in the static pod manifest). Implemented here rather than in secrets.go: it
// shares this file's static-pod discovery, flag parsing and managed-cluster degradation wholesale,
// not any of secrets.go's workload/ConfigMap machinery — see secrets.go's doc comment for the full
// reasoning. Its catalog entry (catalog.yaml) keeps category: "secrets" unchanged; only the Go
// implementation moved.
func (encryptionAtRestCheck) Run(snap *snapshot.Snapshot) Result {
	return controlPlaneFlagResult(snap, apiserverNamePrefix, apiserverComponent, "fail", func(flags map[string]string) bool {
		v, ok := flags["encryption-provider-config"]
		return ok && v != ""
	})
}
