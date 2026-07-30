// rbac.go implements the KG-RB-* checks (RBAC posture): cluster-admin ClusterRoleBindings granted
// to non-system subjects, wildcard verbs/apiGroups in (Cluster)Roles, get/list/watch access to
// secrets, automount on the "default" ServiceAccount, create-pods grants in namespaces holding
// secrets (KG-RB-004, via podCreateRoleResolver — the minimal binding→role→rules resolution that
// check needs) and non-default bindings to the system:authenticated group (KG-RB-005, via the
// systemAuthenticatedDefaultBindings bootstrap allowlist). It also derives report.RbacFinding
// entries (RbacFindings) from the same binding/role analysis.
//
// KG-RB-004/005 were originally left out of M2 (catalog entries with no Go implementation behind
// them) and closed on 2026-07-10: RB-004's blocker fell to a scoped resolver that
// only answers "does this roleRef grant create pods" (no aggregation/resourceNames modeling), and
// RB-005's to the same name+shape allowlist pattern KG-RB-001 already used for kubeadm.
package checks

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// isSystemSubject reports whether an RBAC subject counts as a "system" identity that should be
// excluded from KG-RB-001/RbacFindings: the system:masters group and system:*-prefixed
// Users/Groups (the cluster's own control-plane components), or a ServiceAccount that lives in a
// system namespace.
func isSystemSubject(s rbacv1.Subject) bool {
	switch s.Kind {
	case rbacv1.GroupKind:
		return s.Name == "system:masters" || strings.HasPrefix(s.Name, "system:")
	case rbacv1.UserKind:
		return strings.HasPrefix(s.Name, "system:")
	case rbacv1.ServiceAccountKind:
		return isSystemNamespace(s.Namespace)
	default:
		return false
	}
}

// knownDefaultRoleNames are built-in (Cluster)Roles whose entire purpose is broad access;
// flagging their definitions here would be redundant noise — cluster-admin's dangerous *bindings*
// are what KG-RB-001 checks, and admin/edit/view ship on every cluster.
var knownDefaultRoleNames = map[string]bool{
	"cluster-admin": true,
	"admin":         true,
	"edit":          true,
	"view":          true,
}

// isCustomRoleName reports whether a (Cluster)Role name is neither a Kubernetes system role
// (system:* prefix) nor one of the well-known default aggregate roles.
func isCustomRoleName(name string) bool {
	return !knownDefaultRoleNames[name] && !strings.HasPrefix(name, "system:")
}

func ruleHasWildcard(rule rbacv1.PolicyRule) bool {
	for _, v := range rule.Verbs {
		if v == "*" {
			return true
		}
	}
	for _, g := range rule.APIGroups {
		if g == "*" {
			return true
		}
	}
	return false
}

// ruleGrantsSecretsRead reports whether a PolicyRule grants get/list/watch on secrets in the core
// API group.
func ruleGrantsSecretsRead(rule rbacv1.PolicyRule) bool {
	hasCoreGroup := false
	for _, g := range rule.APIGroups {
		if g == "" || g == "*" {
			hasCoreGroup = true
		}
	}
	if !hasCoreGroup {
		return false
	}

	hasSecretsResource := false
	for _, res := range rule.Resources {
		if res == "secrets" || res == "*" {
			hasSecretsResource = true
		}
	}
	if !hasSecretsResource {
		return false
	}

	for _, v := range rule.Verbs {
		if v == "get" || v == "list" || v == "watch" || v == "*" {
			return true
		}
	}
	return false
}

// knownDistroDefaultBindings documents ClusterRoleBindings that grant cluster-admin as an expected
// part of a Kubernetes distribution's own bootstrap process — not something an operator
// configured — keyed by the binding's exact name and mapped to the exact Group subject name that
// binding is expected to carry. clusterAdminBindingCheck.Run and RbacFindings (below) both
// downgrade a binding matching this from fail/critical to warn/medium: still worth surfacing
// (group membership can be widened or abused later), but not reported as a misconfiguration the
// way an arbitrary custom binding is.
//
//   - "kubeadm:cluster-admins": since kubeadm v1.29, `kubeadm init`/`join` no longer grants
//     cluster-admin directly to a "kubernetes-admin" User; it instead creates this
//     ClusterRoleBinding against a "kubeadm:cluster-admins" Group, and issues admin.conf's client
//     certificate with that Group as its certificate O= (organization). It ships, unconditionally,
//     on every kubeadm-bootstrapped cluster from that version on — the kubeadm equivalent of the
//     cluster-admin -> system:masters default this check already excludes outright.
var knownDistroDefaultBindings = map[string]string{
	"kubeadm:cluster-admins": "kubeadm:cluster-admins",
}

// knownDistroDefaultBindingReason is the RbacFinding.Reason used whenever
// isKnownDistroDefaultBinding matches, in the same audience-facing voice as this file's other
// Reason strings.
const knownDistroDefaultBindingReason = "Default binding created by kubeadm (>=1.29), granting cluster-admin to the kubeadm:cluster-admins group used by the admin.conf certificate — expected on kubeadm clusters, not an operator misconfiguration. Still worth auditing who has access to that group/certificate."

// isKnownDistroDefaultBinding reports whether crb — together with its already-computed set of
// non-system ("offending") subjects — matches a knownDistroDefaultBindings entry exactly. Both the
// binding's name AND every offending subject must match:
//
//   - requiring every offending subject to be the expected Group (not just one of them) means a
//     binding that happens to share the well-known name but was edited to also grant, say, an
//     arbitrary User isn't given the downgrade;
//   - requiring the binding's own name to match (not just the Group name) means a differently-
//     named, custom binding that happens to grant the same well-known Group is still treated as a
//     regular fail/critical finding — see rbac_test.go's "same group via another custom binding"
//     case.
func isKnownDistroDefaultBinding(crb rbacv1.ClusterRoleBinding, offendingSubjects []rbacv1.Subject) bool {
	wantGroup, ok := knownDistroDefaultBindings[crb.Name]
	if !ok || len(offendingSubjects) == 0 {
		return false
	}
	for _, s := range offendingSubjects {
		if s.Kind != rbacv1.GroupKind || s.Name != wantGroup {
			return false
		}
	}
	return true
}

// ---- KG-RB-001: cluster-admin bindings to non-system subjects ---------------------------------

type clusterAdminBindingCheck struct{}

func (clusterAdminBindingCheck) ID() string { return "KG-RB-001" }

// Run flags ClusterRoleBindings granting the built-in cluster-admin ClusterRole to any subject
// outside the expected system identities. The default cluster-admin -> system:masters binding
// that ships with every cluster is intentionally excluded. A binding matching
// knownDistroDefaultBindings (currently just kubeadm's "kubeadm:cluster-admins") is downgraded to
// warn instead of fail — still listed in AffectedResources for visibility, since group membership
// is worth knowing about even when expected — but doesn't by itself make the check fail. A single
// genuinely custom offending binding still fails the whole check (with any known-default binding,
// if present, still included alongside it in the resource list — see rbac_test.go).
func (clusterAdminBindingCheck) Run(snap *snapshot.Snapshot) Result {
	var failBindings, warnBindings []string
	nsSet := map[string]bool{}

	for _, crb := range snap.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "cluster-admin" {
			continue
		}
		var offending []rbacv1.Subject
		for _, subj := range crb.Subjects {
			if !isSystemSubject(subj) {
				offending = append(offending, subj)
				if subj.Kind == rbacv1.ServiceAccountKind && subj.Namespace != "" {
					nsSet[subj.Namespace] = true
				}
			}
		}
		if len(offending) == 0 {
			continue
		}
		if isKnownDistroDefaultBinding(crb, offending) {
			warnBindings = append(warnBindings, "clusterrolebinding/"+crb.Name)
		} else {
			failBindings = append(failBindings, "clusterrolebinding/"+crb.Name)
		}
	}

	switch {
	case len(failBindings) > 0:
		all := append(append([]string(nil), failBindings...), warnBindings...)
		sort.Strings(all)
		return Result{Status: "fail", Namespaces: sortedKeys(nsSet), AffectedResources: all}
	case len(warnBindings) > 0:
		sort.Strings(warnBindings)
		return Result{Status: "warn", Namespaces: sortedKeys(nsSet), AffectedResources: warnBindings}
	default:
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
}

// ---- KG-RB-002: wildcard verbs/apiGroups in (Cluster)Roles -------------------------------------

type wildcardRoleCheck struct{}

func (wildcardRoleCheck) ID() string { return "KG-RB-002" }

func (wildcardRoleCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}

	for _, cr := range snap.ClusterRoles {
		if !isCustomRoleName(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			if ruleHasWildcard(rule) {
				resources = append(resources, "clusterrole/"+cr.Name)
				break
			}
		}
	}
	for _, r := range snap.Roles {
		if !isCustomRoleName(r.Name) {
			continue
		}
		for _, rule := range r.Rules {
			if ruleHasWildcard(rule) {
				resources = append(resources, "role/"+r.Namespace+"/"+r.Name)
				nsSet[r.Namespace] = true
				break
			}
		}
	}

	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: "fail", Namespaces: sortedKeys(nsSet), AffectedResources: resources}
}

// ---- KG-RB-006: get/list/watch on secrets ------------------------------------------------------

type secretsAccessRoleCheck struct{}

func (secretsAccessRoleCheck) ID() string { return "KG-RB-006" }

func (secretsAccessRoleCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}

	for _, cr := range snap.ClusterRoles {
		if !isCustomRoleName(cr.Name) {
			continue
		}
		for _, rule := range cr.Rules {
			if ruleGrantsSecretsRead(rule) {
				resources = append(resources, "clusterrole/"+cr.Name)
				break
			}
		}
	}
	for _, r := range snap.Roles {
		if !isCustomRoleName(r.Name) {
			continue
		}
		for _, rule := range r.Rules {
			if ruleGrantsSecretsRead(rule) {
				resources = append(resources, "role/"+r.Namespace+"/"+r.Name)
				nsSet[r.Namespace] = true
				break
			}
		}
	}

	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: "fail", Namespaces: sortedKeys(nsSet), AffectedResources: resources}
}

// ---- KG-RB-005: system:authenticated granted roles beyond the API server defaults --------------

// systemAuthenticatedDefaultBindings are the ClusterRoleBindings the API server's own RBAC
// bootstrap controller creates against the system:authenticated group on every cluster since
// v1.14: basic-user (SelfSubjectAccessReview/SelfSubjectRulesReview), discovery (API discovery
// endpoints) and public-info-viewer (/version, /healthz, /livez, /readyz). A binding only counts
// as one of these when BOTH its name matches AND it carries the
// kubernetes.io/bootstrapping=rbac-defaults label the bootstrap controller stamps on everything
// it creates: a manually recreated binding with the same name (no label) is flagged, and a custom
// binding granting the same role under another name is flagged too — mirroring
// isKnownDistroDefaultBinding's name+shape double-match above.
var systemAuthenticatedDefaultBindings = map[string]bool{
	"system:basic-user":         true,
	"system:discovery":          true,
	"system:public-info-viewer": true,
}

// isBootstrapDefaultBinding reports whether a ClusterRoleBinding is one of the API server's own
// rbac-defaults bootstrap bindings for system:authenticated (see
// systemAuthenticatedDefaultBindings).
func isBootstrapDefaultBinding(name string, labels map[string]string) bool {
	return systemAuthenticatedDefaultBindings[name] && labels["kubernetes.io/bootstrapping"] == "rbac-defaults"
}

// bindsSystemAuthenticated reports whether any subject is the system:authenticated Group.
func bindsSystemAuthenticated(subjects []rbacv1.Subject) bool {
	for _, s := range subjects {
		if s.Kind == rbacv1.GroupKind && s.Name == "system:authenticated" {
			return true
		}
	}
	return false
}

type systemAuthenticatedBindingCheck struct{}

func (systemAuthenticatedBindingCheck) ID() string { return "KG-RB-005" }

// Run flags every (Cluster)RoleBinding granting a role to the system:authenticated group beyond
// the API server's three bootstrap bindings. system:authenticated includes EVERY authenticated
// identity — all ServiceAccounts included — so a custom grant to it is effectively cluster-wide
// (the 2024 GKE exposure vector the catalog entry for this id describes).
func (systemAuthenticatedBindingCheck) Run(snap *snapshot.Snapshot) Result {
	var resources []string
	nsSet := map[string]bool{}

	for _, crb := range snap.ClusterRoleBindings {
		if !bindsSystemAuthenticated(crb.Subjects) || isBootstrapDefaultBinding(crb.Name, crb.Labels) {
			continue
		}
		resources = append(resources, "clusterrolebinding/"+crb.Name)
	}
	for _, rb := range snap.RoleBindings {
		if !bindsSystemAuthenticated(rb.Subjects) {
			continue
		}
		resources = append(resources, "rolebinding/"+rb.Namespace+"/"+rb.Name)
		nsSet[rb.Namespace] = true
	}

	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: "fail", Namespaces: sortedKeys(nsSet), AffectedResources: resources}
}

// ---- KG-RB-003: automount on the "default" ServiceAccount --------------------------------------

type automountDefaultSACheck struct{}

func (automountDefaultSACheck) ID() string { return "KG-RB-003" }

// Run flags the "default" ServiceAccount in every non-system namespace whose
// automountServiceAccountToken is not explicitly disabled (nil or true = effective automount, the
// Kubernetes default). System namespaces are excluded: several kube-system controllers rely on
// their default SA's token. This only inspects the ServiceAccount object itself ("efetivo" at the
// SA level, per PLAN-FASE-2.md §6) — not a per-pod override scan, which the snapshot doesn't need
// beyond what M1 already collects.
func (automountDefaultSACheck) Run(snap *snapshot.Snapshot) Result {
	var flaggedNs []string
	for _, sa := range snap.ServiceAccounts {
		if sa.Name != "default" || isSystemNamespace(sa.Namespace) {
			continue
		}
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			flaggedNs = append(flaggedNs, sa.Namespace)
		}
	}
	if len(flaggedNs) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(flaggedNs)
	resources := make([]string, 0, len(flaggedNs))
	for _, ns := range flaggedNs {
		resources = append(resources, "sa/"+ns+"/default")
	}
	return Result{Status: "warn", Namespaces: flaggedNs, AffectedResources: resources}
}

// ---- KG-RB-004: create-pods grants in namespaces holding secrets -------------------------------

// ruleGrantsPodCreate reports whether a single PolicyRule allows `create` on core-group `pods`
// (wildcards included). resourceNames-restricted rules still count: create is not meaningfully
// restrictable by resourceName, and erring on the side of surfacing is the point of this check.
func ruleGrantsPodCreate(rule rbacv1.PolicyRule) bool {
	groupOK, resourceOK, verbOK := false, false, false
	for _, g := range rule.APIGroups {
		if g == "" || g == "*" {
			groupOK = true
			break
		}
	}
	for _, r := range rule.Resources {
		if r == "pods" || r == "*" {
			resourceOK = true
			break
		}
	}
	for _, v := range rule.Verbs {
		if v == "create" || v == "*" {
			verbOK = true
			break
		}
	}
	return groupOK && resourceOK && verbOK
}

// podCreateRoleResolver answers "does this RoleRef grant create pods?" over the snapshot's
// (Cluster)Roles — the tiny slice of an RBAC authorizer this check needs: it resolves a binding's
// roleRef to its rules (Role scoped to the binding's namespace, ClusterRole global) without
// modeling aggregation or resourceNames. A roleRef pointing at a role missing from the snapshot
// resolves to "no grant" (the API server treats dangling refs the same way).
type podCreateRoleResolver struct {
	clusterRoles map[string][]rbacv1.PolicyRule
	roles        map[string][]rbacv1.PolicyRule // key: namespace + "/" + name
}

func newPodCreateRoleResolver(snap *snapshot.Snapshot) podCreateRoleResolver {
	r := podCreateRoleResolver{
		clusterRoles: make(map[string][]rbacv1.PolicyRule, len(snap.ClusterRoles)),
		roles:        make(map[string][]rbacv1.PolicyRule, len(snap.Roles)),
	}
	for _, cr := range snap.ClusterRoles {
		r.clusterRoles[cr.Name] = cr.Rules
	}
	for _, role := range snap.Roles {
		r.roles[role.Namespace+"/"+role.Name] = role.Rules
	}
	return r
}

// grantsPodCreate resolves ref (from a binding living in bindingNamespace; "" for a
// ClusterRoleBinding) and reports whether any of its rules grants create pods.
func (r podCreateRoleResolver) grantsPodCreate(ref rbacv1.RoleRef, bindingNamespace string) bool {
	var rules []rbacv1.PolicyRule
	if ref.Kind == "ClusterRole" {
		rules = r.clusterRoles[ref.Name]
	} else {
		rules = r.roles[bindingNamespace+"/"+ref.Name]
	}
	for _, rule := range rules {
		if ruleGrantsPodCreate(rule) {
			return true
		}
	}
	return false
}

// hasNonSystemSubject reports whether at least one subject is not a system identity.
func hasNonSystemSubject(subjects []rbacv1.Subject) bool {
	for _, s := range subjects {
		if !isSystemSubject(s) {
			return true
		}
	}
	return false
}

// secretBearingNamespaces returns the non-system namespaces the agent can PROVE hold at least one
// Secret WITHOUT ever reading Secrets — the ClusterRole grants no access to them (see
// charts/kubegauge-agent/templates/rbac.yaml and internal/snapshot's package doc). A namespace
// qualifies when an object the agent does read references a Secret there: a pod spec (secret and
// projected-secret volumes, CSI node-publish secrets, imagePullSecrets, env/envFrom secret refs),
// a ServiceAccount (secrets/imagePullSecrets) or an Ingress TLS block.
//
// This is a deliberate under-approximation: a Secret nothing references is invisible to the agent,
// so KG-RB-004 can miss a namespace whose only Secrets are unused. Losing that recall is the price
// of not shipping a cluster-wide secret-read credential into every customer cluster — the very
// grant KG-RB-006 fails a Role for. Referenced Secrets are also the ones that matter most here:
// they hold the credentials a pod-create grant would let a subject mount and read.
func secretBearingNamespaces(snap *snapshot.Snapshot) map[string]bool {
	out := map[string]bool{}
	mark := func(ns string) {
		if ns != "" && !isSystemNamespace(ns) {
			out[ns] = true
		}
	}

	markPodSpec := func(ns string, spec *corev1.PodSpec) {
		if len(spec.ImagePullSecrets) > 0 {
			mark(ns)
		}
		for _, v := range spec.Volumes {
			if v.Secret != nil || (v.CSI != nil && v.CSI.NodePublishSecretRef != nil) {
				mark(ns)
			}
			if v.Projected != nil {
				for _, src := range v.Projected.Sources {
					if src.Secret != nil {
						mark(ns)
					}
				}
			}
		}
		for _, c := range spec.Containers {
			if containerConsumesSecretViaEnv(c.EnvFrom, c.Env) {
				mark(ns)
			}
		}
		for _, c := range spec.InitContainers {
			if containerConsumesSecretViaEnv(c.EnvFrom, c.Env) {
				mark(ns)
			}
		}
	}

	// Pod templates (Deployments/StatefulSets/DaemonSets) and ownerless Pods...
	for _, src := range report.WorkloadSources(snap) {
		spec := src.Spec
		markPodSpec(src.Namespace, &spec)
	}
	// ...plus every live Pod, which also covers ReplicaSet/Job/CronJob-owned pods.
	for i := range snap.Pods {
		markPodSpec(snap.Pods[i].Namespace, &snap.Pods[i].Spec)
	}
	for _, sa := range snap.ServiceAccounts {
		if len(sa.Secrets) > 0 || len(sa.ImagePullSecrets) > 0 {
			mark(sa.Namespace)
		}
	}
	for _, ing := range snap.Ingresses {
		for _, tls := range ing.Spec.TLS {
			if tls.SecretName != "" {
				mark(ing.Namespace)
			}
		}
	}
	return out
}

type podCreateInSecretNamespacesCheck struct{}

func (podCreateInSecretNamespacesCheck) ID() string { return "KG-RB-004" }

// Run surfaces every binding that lets a non-system subject create pods in a non-system namespace
// holding at least one Secret — `create pods` means mounting (and reading) any Secret of that
// namespace, per this id's catalog entry. "Holding a Secret" is decided by secretBearingNamespaces
// above, which infers it from references instead of listing Secrets (see its doc comment for the
// recall this trades away, and why). It reports **warn**, not fail: a create-pods grant is
// sometimes legitimate (CI/CD deployers, workflow engines), so this is an "audite isso" signal in
// the same spirit as KG-RB-003, unlike the binary misconfigurations KG-RB-001/002/005/006 fail
// on. RoleBindings are checked against their own namespace; a ClusterRoleBinding grants
// cluster-wide, so it's reported against every secret-bearing non-system namespace at once.
func (podCreateInSecretNamespacesCheck) Run(snap *snapshot.Snapshot) Result {
	secretNs := secretBearingNamespaces(snap)
	if len(secretNs) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}

	resolver := newPodCreateRoleResolver(snap)
	var resources []string
	nsSet := map[string]bool{}

	for _, crb := range snap.ClusterRoleBindings {
		if !hasNonSystemSubject(crb.Subjects) || !resolver.grantsPodCreate(crb.RoleRef, "") {
			continue
		}
		resources = append(resources, "clusterrolebinding/"+crb.Name)
		for ns := range secretNs {
			nsSet[ns] = true
		}
	}
	for _, rb := range snap.RoleBindings {
		if !secretNs[rb.Namespace] || isSystemNamespace(rb.Namespace) {
			continue
		}
		if !hasNonSystemSubject(rb.Subjects) || !resolver.grantsPodCreate(rb.RoleRef, rb.Namespace) {
			continue
		}
		resources = append(resources, "rolebinding/"+rb.Namespace+"/"+rb.Name)
		nsSet[rb.Namespace] = true
	}

	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: "warn", Namespaces: sortedKeys(nsSet), AffectedResources: resources}
}

// ---- RbacFindings: per-(binding,subject) findings for the RBAC page ----------------------------

// roleRefKey builds a stable key identifying a (Cluster)Role: "ClusterRole/<name>" or
// "Role/<namespace>/<name>". bindingNamespace is only used when ref.Kind == "Role" (a namespaced
// Role is scoped to its RoleBinding's own namespace by definition).
func roleRefKey(ref rbacv1.RoleRef, bindingNamespace string) string {
	if ref.Kind == "ClusterRole" {
		return "ClusterRole/" + ref.Name
	}
	return "Role/" + bindingNamespace + "/" + ref.Name
}

// riskyRoleSets indexes every custom (Cluster)Role matching the wildcard or secrets-read pattern
// (see wildcardRoleCheck/secretsAccessRoleCheck above) by the same key roleRefKey produces, so
// RbacFindings can tell whether a binding's RoleRef points at one of them.
func riskyRoleSets(snap *snapshot.Snapshot) (wildcard map[string]bool, secrets map[string]bool) {
	wildcard = map[string]bool{}
	secrets = map[string]bool{}

	for _, cr := range snap.ClusterRoles {
		if !isCustomRoleName(cr.Name) {
			continue
		}
		key := "ClusterRole/" + cr.Name
		for _, rule := range cr.Rules {
			if ruleHasWildcard(rule) {
				wildcard[key] = true
			}
			if ruleGrantsSecretsRead(rule) {
				secrets[key] = true
			}
		}
	}
	for _, r := range snap.Roles {
		if !isCustomRoleName(r.Name) {
			continue
		}
		key := "Role/" + r.Namespace + "/" + r.Name
		for _, rule := range r.Rules {
			if ruleHasWildcard(rule) {
				wildcard[key] = true
			}
			if ruleGrantsSecretsRead(rule) {
				secrets[key] = true
			}
		}
	}
	return wildcard, secrets
}

// riskyRoleReason returns the RbacFinding reason/risk for a role key already known to be risky
// (ok=false if it matches neither pattern). Wildcard takes priority when a role matches both,
// since granting "*" already implies the secrets access too.
func riskyRoleReason(key string, wildcard, secrets map[string]bool) (reason string, risk string, ok bool) {
	switch {
	case wildcard[key]:
		return `Role grants wildcard ("*") verbs and/or apiGroups, equivalent to unrestricted access to the resources it covers.`, "high", true
	case secrets[key]:
		return "Role grants get/list/watch on secrets, exposing namespace credentials to whoever assumes this binding.", "high", true
	default:
		return "", "", false
	}
}

// RbacFindings derives report.RbacFinding entries from the same RBAC analysis as the KG-RB-*
// checks above (cluster-admin bindings, wildcard roles, secrets-reading roles) — one finding per
// (binding, subject) pair actually granting the risky role, which is the shape RbacFinding
// requires (subject + binding + role, not just a role definition). KG-RB-003 (default SA
// automount) has no natural binding/role to report here — automount is a ServiceAccount property,
// not a role grant — so it is represented only in checks[] (KG-RB-003), never duplicated into
// rbacFindings.
//
// Findings are sorted by (bindingKind, binding, subject) before sequential ids are assigned, so
// RB-F-NNN numbering is deterministic regardless of the snapshot's internal slice order.
func RbacFindings(snap *snapshot.Snapshot) []report.RbacFinding {
	wildcardRoles, secretsRoles := riskyRoleSets(snap)

	drafts := []report.RbacFinding{}

	for _, crb := range snap.ClusterRoleBindings {
		if crb.RoleRef.Kind != "ClusterRole" {
			continue
		}

		if crb.RoleRef.Name == "cluster-admin" {
			var offending []rbacv1.Subject
			for _, subj := range crb.Subjects {
				if !isSystemSubject(subj) {
					offending = append(offending, subj)
				}
			}
			risk, reason := "critical", "Grants cluster-admin (full control of the cluster) to a subject outside the expected system identities."
			if isKnownDistroDefaultBinding(crb, offending) {
				risk, reason = "medium", knownDistroDefaultBindingReason
			}
			for _, subj := range offending {
				drafts = append(drafts, report.RbacFinding{
					Subject:     subj.Name,
					SubjectKind: subj.Kind,
					Binding:     crb.Name,
					BindingKind: "ClusterRoleBinding",
					Role:        "cluster-admin",
					Risk:        risk,
					Reason:      reason,
				})
			}
			continue
		}

		key := "ClusterRole/" + crb.RoleRef.Name
		if reason, risk, ok := riskyRoleReason(key, wildcardRoles, secretsRoles); ok {
			for _, subj := range crb.Subjects {
				drafts = append(drafts, report.RbacFinding{
					Subject:     subj.Name,
					SubjectKind: subj.Kind,
					Binding:     crb.Name,
					BindingKind: "ClusterRoleBinding",
					Role:        crb.RoleRef.Name,
					Risk:        risk,
					Reason:      reason,
				})
			}
		}
	}

	for _, rb := range snap.RoleBindings {
		key := roleRefKey(rb.RoleRef, rb.Namespace)
		if reason, risk, ok := riskyRoleReason(key, wildcardRoles, secretsRoles); ok {
			for _, subj := range rb.Subjects {
				drafts = append(drafts, report.RbacFinding{
					Subject:     subj.Name,
					SubjectKind: subj.Kind,
					Binding:     rb.Name,
					BindingKind: "RoleBinding",
					Role:        rb.RoleRef.Name,
					Risk:        risk,
					Reason:      reason,
				})
			}
		}
	}

	sort.Slice(drafts, func(i, j int) bool {
		if drafts[i].BindingKind != drafts[j].BindingKind {
			return drafts[i].BindingKind < drafts[j].BindingKind
		}
		if drafts[i].Binding != drafts[j].Binding {
			return drafts[i].Binding < drafts[j].Binding
		}
		return drafts[i].Subject < drafts[j].Subject
	})

	for i := range drafts {
		drafts[i].ID = fmt.Sprintf("RB-F-%03d", i+1)
	}
	return drafts
}
