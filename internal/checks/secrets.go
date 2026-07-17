// secrets.go implements two of the three KG-SE-* checks (Secrets & Data): how workloads consume
// Secrets (env vars vs. volumes) and a credential-name heuristic over ConfigMap KEY NAMES only.
//
// KG-SE-001 ("Encryption at rest habilitada para secrets no etcd") is implemented in
// controlplane.go instead (M4), not here: it audits the kube-apiserver's --encryption-provider-
// config flag via the exact same static-pod-discovery/flag-parsing/managed-cluster-degradation
// machinery as the KG-CP-* checks, so it is colocated with that mechanism for one implementation
// rather than duplicated (or made to import controlplane.go's unexported helpers across files for
// no benefit). Its catalog entry (catalog.yaml) is unaffected — category stays "secrets", matching
// client/src/data/checks.ts, which seeds it under Secrets & Data, not Control Plane. Only the .go
// file implementing its Check moved.
//
// KG-SE-002 and KG-SE-003 are both computable purely from workload/ConfigMap objects (no
// control-plane access needed) and are implemented below.
//
// SECURITY-CRITICAL INVARIANT: this file must never read, compare, log, or otherwise handle a
// Secret's or ConfigMap's VALUES. It only ever sees snapshot.SecretMeta (name/namespace/type) and
// snapshot.ConfigMapMeta (name/namespace/key NAMES) — see snapshot.go's doc comment for the
// guarantee that those are the only shapes a Secret/ConfigMap can take once collected, and
// snapshot/snapshot_test.go's TestSecretValuesNeverLeaveSnapshot for the test enforcing it.
package checks

import (
	"regexp"

	corev1 "k8s.io/api/core/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// ---- KG-SE-002: secrets consumed via env vars vs. volumes --------------------------------------

type secretsViaEnvCheck struct{}

func (secretsViaEnvCheck) ID() string { return "KG-SE-002" }

// Run flags every workload (outside system namespaces) with at least one container or init
// container that consumes a Secret via envFrom.secretRef or env[].valueFrom.secretKeyRef, mirroring
// the mock's own audit command (which only checks env[].valueFrom.secretKeyRef; envFrom.secretRef
// is the same anti-pattern at the container level and is included here for completeness — a
// deliberate, documented widening, not an invented new concept). This inspects only how a Secret is
// *referenced* from a pod spec, never its value: no Secret content is read to make this
// determination. warn (not fail): mounting via env is common practice and not itself a critical
// vulnerability, matching the mock's own medium severity.
func (secretsViaEnvCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, src := range report.WorkloadSources(snap) {
		if isSystemNamespace(src.Namespace) {
			continue
		}
		if workloadConsumesSecretViaEnv(src) {
			resources = append(resources, workloadResourceRef(src.Kind, src.Namespace, src.Name))
			nsSet[src.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "warn")
}

func workloadConsumesSecretViaEnv(src report.WorkloadSource) bool {
	for _, c := range src.Spec.Containers {
		if containerConsumesSecretViaEnv(c.EnvFrom, c.Env) {
			return true
		}
	}
	for _, c := range src.Spec.InitContainers {
		if containerConsumesSecretViaEnv(c.EnvFrom, c.Env) {
			return true
		}
	}
	return false
}

func containerConsumesSecretViaEnv(envFrom []corev1.EnvFromSource, env []corev1.EnvVar) bool {
	for _, ef := range envFrom {
		if ef.SecretRef != nil {
			return true
		}
	}
	for _, e := range env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			return true
		}
	}
	return false
}

// ---- KG-SE-003: credential-name heuristic over ConfigMap keys ----------------------------------

// credentialKeyPattern matches ConfigMap KEY NAMES that look like they hold a credential —
// password|passwd|token|secret|apikey|api_key|credential, case-insensitive, per the task's
// specified heuristic. It is matched ONLY against snapshot.ConfigMapMeta.Keys (names), never
// against any value — see this file's package doc comment.
var credentialKeyPattern = regexp.MustCompile(`(?i)(password|passwd|token|secret|apikey|api_key|credential)`)

type configMapCredentialHeuristicCheck struct{}

func (configMapCredentialHeuristicCheck) ID() string { return "KG-SE-003" }

// Run flags every ConfigMap (outside system namespaces) with at least one key name matching
// credentialKeyPattern. warn, not fail: this is a name-based heuristic ("password_policy" or
// "token_ttl_seconds" would match without actually holding a credential value), so it needs human
// review rather than being treated as a confirmed violation — the mock's own explanation frames it
// the same way ("Padrões a caçar", not "sempre é um vazamento").
func (configMapCredentialHeuristicCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, cm := range snap.ConfigMaps {
		if isSystemNamespace(cm.Namespace) {
			continue
		}
		if configMapHasCredentialLikeKey(cm) {
			resources = append(resources, "configmap/"+cm.Namespace+"/"+cm.Name)
			nsSet[cm.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "warn")
}

func configMapHasCredentialLikeKey(cm snapshot.ConfigMapMeta) bool {
	for _, key := range cm.Keys {
		if credentialKeyPattern.MatchString(key) {
			return true
		}
	}
	return false
}
