// Package checks implements the KubeGauge compliance checks: NetworkPolicy (KG-NP-*, netpol.go),
// RBAC (KG-RB-*, rbac.go) and Pod Security Admission (KG-PS-*, psa.go) posture in M2, plus
// SecurityContext (KG-SC-*, secctx.go), Runtime profiles (KG-RT-*, runtime.go), Secrets (KG-SE-*,
// secrets.go) and Supply Chain (KG-SU-*, supplychain.go) in M3, plus Control Plane (KG-CP-*, and
// KG-SE-001 — see secrets.go's doc comment for why it moved — both in controlplane.go) via
// kube-system static pods in M4, plus Versions & Upgrades (KG-VU-*, versions.go) in the platform
// batch. Each Check is a pure function of a snapshot.Snapshot; Run below evaluates every
// registered Check and returns the raw wire results — the push payload. See each category file's
// doc comment for which mock ids were judged infeasible to compute from the snapshot, and why.
package checks

import (
	"sort"
	"strings"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
	"github.com/kubegauge/agent/internal/wire"
)

// Result is a Check's verdict against one snapshot: everything that depends on live cluster
// state (the platform's educational catalog supplies everything else — title, explanation, audit
// command, remediation, docs, framework refs — keyed by the same check id). Namespaces and
// AffectedResources must always be non-nil (the wire contract forbids null here, carried
// through to wire.CheckResult); every concrete Check below is built to guarantee this, and Run
// also normalizes defensively (nonNilStrings).
type Result struct {
	Status            string
	Namespaces        []string
	AffectedResources []string
	// ImageFindings is only set by KG-SU-003 (scanner-fed check); nil for every other check and
	// omitted from the JSON via wire.CheckResult's omitempty.
	ImageFindings []report.ImageVulnFinding
}

// Check is one compliance rule: a stable catalog id (KG-<CAT>-<NNN>) plus a pure function of the
// snapshot.
type Check interface {
	ID() string
	Run(s *snapshot.Snapshot) Result
}

// All is the registry of every implemented check, in catalog order (NP, RBAC, PSA, then the M3
// additions SC, RT, SE, SU, then the M4 addition CP). KG-SE-001 is grouped with the other SE
// checks below (catalog order), even though it's implemented in controlplane.go alongside CP —
// see secrets.go's doc comment for why.
var All = []Check{
	defaultDenyIngressCheck{},
	defaultDenyEgressCheck{},
	cniSupportCheck{},
	kubeSystemIngressProtectedCheck{},
	ipBlockOpenCheck{},

	clusterAdminBindingCheck{},
	wildcardRoleCheck{},
	secretsAccessRoleCheck{},
	automountDefaultSACheck{},
	podCreateInSecretNamespacesCheck{},
	systemAuthenticatedBindingCheck{},

	psaEnforceLabelCheck{},
	privilegedPodCheck{},
	hostPathVolumeCheck{},
	hostNamespacesCheck{},

	runAsNonRootCheck{},
	readOnlyRootFilesystemCheck{},
	capabilitiesDropAllCheck{},
	allowPrivilegeEscalationCheck{},
	resourceLimitsCheck{},

	seccompRuntimeDefaultCheck{},
	appArmorRuntimeDefaultCheck{},
	noUnconfinedProfileCheck{},
	seLinuxOptionsCheck{},

	encryptionAtRestCheck{},
	secretsViaEnvCheck{},
	configMapCredentialHeuristicCheck{},
	externalSecretsManagementCheck{},

	apiserverAnonymousAuthCheck{},
	auditLogPathCheck{},
	etcdClientCertAuthCheck{},
	nodeRestrictionAdmissionCheck{},
	alwaysPullImagesAdmissionCheck{},
	podSecurityNotDisabledCheck{},
	auditPolicyAndRetentionCheck{},
	authorizationModeCheck{},
	profilingDisabledCheck{},
	oidcAuthenticationCheck{},

	mutableImageTagCheck{},
	registryAllowlistCheck{},
	imageVulnScanCheck{},
	imageSignatureVerificationCheck{},

	kubernetesVersionSupportCheck{},

	namespaceResourceQuotaCheck{},
	namespaceLimitRangeCheck{},

	ingressTLSCheck{},

	runtimeThreatDetectionCheck{},

	backupDisasterRecoveryCheck{},
}

// Run evaluates every registered Check and returns the raw wire results (id + runtime verdict
// only) — the push payload. No catalog join happens here: the educational catalog lives in the
// KubeGauge platform and is joined by check id server-side.
func Run(snap *snapshot.Snapshot) []wire.CheckResult {
	out := make([]wire.CheckResult, 0, len(All))
	for _, c := range All {
		res := c.Run(snap)
		out = append(out, wire.CheckResult{
			ID:                c.ID(),
			Status:            res.Status,
			Namespaces:        nonNilStrings(res.Namespaces),
			AffectedResources: nonNilStrings(res.AffectedResources),
			ImageFindings:     res.ImageFindings,
		})
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// isSystemNamespace delegates to snapshot.IsSystemNamespace (moved there for the Trivy
// integration — internal/trivy needs the same exclusion without importing this package).
func isSystemNamespace(ns string) bool {
	return snapshot.IsSystemNamespace(ns)
}

// sortedKeys returns the keys of a namespace set, sorted, defaulting to a non-nil empty slice
// (never nil — see Result's doc comment).
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// workloadKindPrefixes maps a workload Kind (as report.WorkloadPosture/WorkloadSource carry it,
// see report/workload.go) to the lowercase resource-type prefix the mock's own affectedResources
// use for the same categories (e.g. "deploy/default/legacy-api", not
// "deployment/default/legacy-api" — see client/src/data/checks.ts's KG-SC-*/KG-RT-*/KG-SE-*/
// KG-SU-* entries). Shared by every M3 (secctx.go, runtime.go, secrets.go, supplychain.go) check
// below, all of which iterate the same report.WorkloadSources/BuildWorkloads output.
var workloadKindPrefixes = map[string]string{
	"Deployment":  "deploy",
	"StatefulSet": "statefulset",
	"DaemonSet":   "daemonset",
	"Pod":         "pod",
}

// workloadResourceRef formats a workload identity as "<prefix>/<namespace>/<name>". Falls back to
// the lowercased kind for any kind workloadKindPrefixes doesn't recognize (defensive: every kind
// report.WorkloadSources can currently produce is listed above, so this path is not expected to be
// hit against a real snapshot).
func workloadResourceRef(kind, namespace, name string) string {
	prefix, ok := workloadKindPrefixes[kind]
	if !ok {
		prefix = strings.ToLower(kind)
	}
	return prefix + "/" + namespace + "/" + name
}

// workloadSetResult builds a Result from a set of violating workload resource refs (already
// formatted by workloadResourceRef) and the namespaces they belong to: status when non-empty,
// "pass" when empty. The M3, workload-based equivalent of namespaceResult (netpol.go).
func workloadSetResult(resources []string, namespaces map[string]bool, status string) Result {
	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sorted := append([]string(nil), resources...)
	sort.Strings(sorted)
	return Result{Status: status, Namespaces: sortedKeys(namespaces), AffectedResources: sorted}
}
