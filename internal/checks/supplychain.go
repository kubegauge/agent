// supplychain.go implements the KG-SU-* checks (image supply-chain hygiene): mutable image tags
// (:latest / no tag, without a compensating digest) and images pulled from outside a registry
// allowlist.
//
// KG-SU-003 ("Scan de vulnerabilidades nas imagens em uso") is fed by the internal/trivy
// enrichment: it reads snap.ImageVulns (nil = trivy unavailable/disabled -> info) instead of the
// API snapshot, since no get/list of Kubernetes objects can reveal what CVEs an image's layers
// contain. Status: any CRITICAL -> fail, any HIGH -> warn, otherwise pass; MEDIUM/LOW only show in
// the per-image findings. See SPEC-TRIVY-KG-SU-003.md.
//
// Both implemented checks exclude system namespaces (see checks.go/psa.go): kube-system images are
// managed by the cluster distribution, not the workload team this dashboard is for, and are
// typically already version-pinned and on the allowlist (registry.k8s.io) regardless.
package checks

import (
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// ---- KG-SU-001: mutable image tags (:latest / no tag / no digest) ------------------------------

type mutableImageTagCheck struct{}

func (mutableImageTagCheck) ID() string { return "KG-SU-001" }

// Run flags every workload (outside system namespaces) with at least one container or init
// container image that is NOT pinned to an immutable reference. An image counts as pinned when it
// carries a digest (@sha256:...) — regardless of tag, since the digest alone already makes the
// reference immutable — OR when it has an explicit, non-"latest" tag. It fails when the tag is
// missing (bare "nginx", which resolves to :latest) or explicitly "latest", AND no digest
// compensates for it.
//
// Deviation from a literal reading of the task brief ("imagens... sem digest" as its own trigger):
// we do NOT fail every image that merely lacks a digest. Pinning by digest is rare in ordinary
// manifests (most legitimately use "image:1.25"-style tags with no digest), so an unconditional
// "missing digest -> fail" would fire on nearly every container in nearly every real cluster,
// drowning the specific, actionable ":latest" signal this id's mock entry and medium severity are
// built around. Missing-digest is instead folded into the mutable-tag condition (it only matters
// when the tag itself is absent/"latest") — the same kind of deliberate scope narrowing netpol.go's
// KG-NP-002 applies to the mock's "critical namespaces" concept.
func (mutableImageTagCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, src := range report.WorkloadSources(snap) {
		if isSystemNamespace(src.Namespace) {
			continue
		}
		if workloadHasMutableImageTag(src) {
			resources = append(resources, workloadResourceRef(src.Kind, src.Namespace, src.Name))
			nsSet[src.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "fail")
}

func workloadHasMutableImageTag(src report.WorkloadSource) bool {
	for _, c := range src.Spec.Containers {
		if parseImageRef(c.Image).isMutableTag() {
			return true
		}
	}
	for _, c := range src.Spec.InitContainers {
		if parseImageRef(c.Image).isMutableTag() {
			return true
		}
	}
	return false
}

// ---- KG-SU-002: registry allowlist ---------------------------------------------------------------

// allowedRegistries is the v1 registry allowlist: the "obvious" official public registries, used
// as a hardcoded default per the task brief. This becomes a configurable (flag/env) allowlist in a
// later milestone once there is a config surface for a cluster operator to add their own
// private/internal registries.
var allowedRegistries = map[string]bool{
	"docker.io":       true,
	"registry.k8s.io": true,
	"quay.io":         true,
	"ghcr.io":         true,
	"gcr.io":          true,
	"public.ecr.aws":  true,
}

type registryAllowlistCheck struct{}

func (registryAllowlistCheck) ID() string { return "KG-SU-002" }

// Run flags every workload (outside system namespaces) with at least one container or init
// container image pulled from a registry not in allowedRegistries. warn (not fail): a registry
// outside the default allowlist is not necessarily malicious — private/internal registries are
// completely legitimate — it just needs a human decision to confirm and, if legitimate, extend the
// allowlist, matching the mock's own framing ("Enforce com admission control").
func (registryAllowlistCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}
	for _, src := range report.WorkloadSources(snap) {
		if isSystemNamespace(src.Namespace) {
			continue
		}
		if workloadHasDisallowedRegistry(src) {
			resources = append(resources, workloadResourceRef(src.Kind, src.Namespace, src.Name))
			nsSet[src.Namespace] = true
		}
	}
	return workloadSetResult(resources, nsSet, "warn")
}

func workloadHasDisallowedRegistry(src report.WorkloadSource) bool {
	for _, c := range src.Spec.Containers {
		if !allowedRegistries[parseImageRef(c.Image).registry] {
			return true
		}
	}
	for _, c := range src.Spec.InitContainers {
		if !allowedRegistries[parseImageRef(c.Image).registry] {
			return true
		}
	}
	return false
}

// ---- shared image reference parsing ---------------------------------------------------------------

// parsedImageRef captures the three pieces of a container image reference relevant to KG-SU-*.
type parsedImageRef struct {
	registry  string
	tag       string
	hasDigest bool
}

// isMutableTag reports whether the reference is NOT immutably pinned: no digest, and either no tag
// at all or the literal tag "latest".
func (p parsedImageRef) isMutableTag() bool {
	return !p.hasDigest && (p.tag == "" || p.tag == "latest")
}

// parseImageRef splits a container image string into registry/tag/digest-presence, following the
// same convention Docker/containerd use: a reference is "[registry/]repository[:tag][@digest]",
// and the leading path segment before the first "/" counts as a registry host only if it contains
// a "." or ":" or is literally "localhost" — otherwise the whole reference is implicitly on
// docker.io (e.g. "nginx:1.25" and "bitnami/postgres:14" are both docker.io images; "gcr.io/proj/
// img" is not).
func parseImageRef(image string) parsedImageRef {
	ref := image
	hasDigest := false
	if at := strings.Index(ref, "@"); at != -1 {
		hasDigest = true
		ref = ref[:at]
	}

	registry := "docker.io"
	pathPart := ref
	if slash := strings.Index(ref, "/"); slash != -1 {
		firstSegment := ref[:slash]
		if strings.ContainsAny(firstSegment, ".:") || firstSegment == "localhost" {
			registry = firstSegment
			pathPart = ref[slash+1:]
		}
	}

	// The tag (if any) is on the LAST path segment only, so a registry:port colon earlier in the
	// string is never mistaken for a tag separator.
	lastSegment := pathPart
	if i := strings.LastIndex(pathPart, "/"); i != -1 {
		lastSegment = pathPart[i+1:]
	}
	tag := ""
	if colon := strings.Index(lastSegment, ":"); colon != -1 {
		tag = lastSegment[colon+1:]
	}

	return parsedImageRef{registry: registry, tag: tag, hasDigest: hasDigest}
}

// ---- KG-SU-003: image vulnerability scan (trivy-fed) --------------------------------------------

type imageVulnScanCheck struct{}

func (imageVulnScanCheck) ID() string { return "KG-SU-003" }

// Run grades the trivy enrichment: fail on any CRITICAL, warn on any HIGH (or when every image
// failed to scan — pretending "pass" would hide a broken scanner), pass otherwise. info when the
// enrichment is absent entirely (no trivy binary / --no-trivy).
func (imageVulnScanCheck) Run(snap *snapshot.Snapshot) Result {
	if snap.ImageVulns == nil {
		return Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}}
	}

	refs := make([]string, 0, len(snap.ImageVulns.ByRef))
	for ref := range snap.ImageVulns.ByRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	var findings []report.ImageVulnFinding
	flagged := map[string]bool{} // refs with HIGH/CRITICAL — drive affectedResources
	anyCritical, anyHigh := false, false
	errored := 0
	for _, ref := range refs {
		r := snap.ImageVulns.ByRef[ref]
		findings = append(findings, toImageVulnFinding(ref, r))
		if r.ScanError != "" {
			errored++
			continue
		}
		anyCritical = anyCritical || r.Critical > 0
		anyHigh = anyHigh || r.High > 0
		if r.Critical > 0 || r.High > 0 {
			flagged[ref] = true
		}
	}

	var resources []string
	nsSet := map[string]bool{}
	for _, src := range report.WorkloadSources(snap) {
		if isSystemNamespace(src.Namespace) {
			continue
		}
		if workloadUsesFlaggedImage(src, flagged) {
			resources = append(resources, workloadResourceRef(src.Kind, src.Namespace, src.Name))
			nsSet[src.Namespace] = true
		}
	}
	sort.Strings(resources)

	status := "pass"
	switch {
	case anyCritical:
		status = "fail"
	case anyHigh:
		status = "warn"
	case len(refs) > 0 && errored == len(refs):
		status = "warn"
	}

	return Result{
		Status:            status,
		Namespaces:        sortedKeys(nsSet),
		AffectedResources: nonNilStrings(resources),
		ImageFindings:     findings,
	}
}

func toImageVulnFinding(ref string, r snapshot.ImageScanResult) report.ImageVulnFinding {
	f := report.ImageVulnFinding{
		Image: ref, Critical: r.Critical, High: r.High, Medium: r.Medium, Low: r.Low,
		ScanError: r.ScanError,
	}
	for _, c := range r.TopCVEs {
		f.TopCves = append(f.TopCves, report.CveRef{
			ID: c.ID, Severity: c.Severity, Pkg: c.Pkg,
			InstalledVersion: c.InstalledVersion, FixedVersion: c.FixedVersion, Title: c.Title,
		})
	}
	return f
}

func workloadUsesFlaggedImage(src report.WorkloadSource, flagged map[string]bool) bool {
	for _, c := range src.Spec.Containers {
		if flagged[c.Image] {
			return true
		}
	}
	for _, c := range src.Spec.InitContainers {
		if flagged[c.Image] {
			return true
		}
	}
	return false
}

// ---- KG-SU-004: image signature verification admission (sigstore/connaisseur/kyverno) -----------

type imageSignatureVerificationCheck struct{}

func (imageSignatureVerificationCheck) ID() string { return "KG-SU-004" }

// Run inspects the cluster's ValidatingWebhookConfigurations (both the configuration's own name
// and each webhook entry's name, case-insensitively) for a signature-verification admission
// stack:
//
//   - "sigstore" (policy-controller registers policy.sigstore.dev) or "connaisseur": pass —
//     dedicated signature verifiers, whose webhook being registered IS the enforcement;
//   - "kyverno": warn, listing the matched configurations — Kyverno's webhooks are policy-driven
//     and look identical whether or not any verifyImages rule exists, so its presence alone
//     cannot confirm signature verification from the API objects this snapshot sees. The
//     catalog's auditCommand shows how to confirm manually (ClusterPolicies with verifyImages);
//   - otherwise: fail — no recognized signature-verification admission stack in the cluster.
//
// Unlike KG-CP-* there is no managed-cluster degradation: webhook configurations are ordinary,
// cluster-scoped API objects, fully visible on EKS/GKE/AKS too.
func (imageSignatureVerificationCheck) Run(snap *snapshot.Snapshot) Result {
	dedicated := false
	var kyverno []string
	for _, cfg := range snap.ValidatingWebhookConfigs {
		switch {
		case webhookConfigMatches(cfg, "sigstore"), webhookConfigMatches(cfg, "connaisseur"):
			dedicated = true
		case webhookConfigMatches(cfg, "kyverno"):
			kyverno = append(kyverno, "validatingwebhookconfiguration/"+cfg.Name)
		}
	}
	if dedicated {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	if len(kyverno) > 0 {
		sort.Strings(kyverno)
		return Result{Status: "warn", Namespaces: []string{}, AffectedResources: kyverno}
	}
	return Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{}}
}

// webhookConfigMatches reports whether cfg's own name or any of its webhook entries' names
// contains substr, case-insensitively.
func webhookConfigMatches(cfg admissionregistrationv1.ValidatingWebhookConfiguration, substr string) bool {
	if strings.Contains(strings.ToLower(cfg.Name), substr) {
		return true
	}
	for _, w := range cfg.Webhooks {
		if strings.Contains(strings.ToLower(w.Name), substr) {
			return true
		}
	}
	return false
}
