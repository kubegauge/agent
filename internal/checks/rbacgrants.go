// rbacgrants.go implements the KG-RB-007..013 checks: RBAC grants the CIS 5.1.x controls tell you
// to minimize. It is the first code in this repo that inspects PolicyRule.Resources, and therefore
// the first that can see a sub-resource such as "nodes/proxy" at all.
package checks

import (
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// grantMatcher describes one RBAC grant a check hunts for. A rule matches when it satisfies all
// three dimensions; "*" on either side of a dimension satisfies it, because a wildcard genuinely
// confers the specific grant. An empty Verbs list means "any verb" — used by the checks whose
// control is about access to the object at all, not about a particular operation.
//
// Wildcard rules therefore match here AND in KG-RB-002 (wildcard verbs/apiGroups). That overlap is
// deliberate: these checks report who HOLDS the access, and a role granting "*" holds it. Silence
// on the grounds that another check might mention the role would be the product hiding something
// it measured.
type grantMatcher struct {
	APIGroups []string
	Resources []string
	Verbs     []string
	// Namespaced marks a target that a RoleBinding can actually confer. RBAC consults a RoleBinding
	// only for requests inside its own namespace, so a RoleBinding grants nothing on a
	// cluster-scoped resource — nodes/proxy, persistentvolumes,
	// certificatesigningrequests/approval and the webhook configurations — no matter which role it
	// points at, and no matter that the role's rules name them. Reporting such a binding would
	// hand the operator an object to edit for access it does not confer, and the finding would
	// never clear because there is nothing there to fix.
	//
	// Only set this for resources that live in a namespace: serviceaccounts (and their token
	// sub-resource), roles and rolebindings.
	Namespaced bool
}

// namespacedMatchers returns the subset of matchers a RoleBinding can actually confer. An empty
// result means the RoleBindings loop has nothing to look for and can be skipped entirely.
func namespacedMatchers(matchers []grantMatcher) []grantMatcher {
	var out []grantMatcher
	for _, m := range matchers {
		if m.Namespaced {
			out = append(out, m)
		}
	}
	return out
}

// matchesAny reports whether want appears in got, treating "*" in got as matching anything.
func matchesAny(got []string, want []string) bool {
	for _, g := range got {
		if g == "*" {
			return true
		}
		for _, w := range want {
			if g == w {
				return true
			}
		}
	}
	return false
}

// ruleMatchesGrant reports whether rule confers the grant m describes.
func ruleMatchesGrant(rule rbacv1.PolicyRule, m grantMatcher) bool {
	if !matchesAny(rule.APIGroups, m.APIGroups) {
		return false
	}
	if !matchesAny(rule.Resources, m.Resources) {
		return false
	}
	if len(m.Verbs) == 0 {
		return true
	}
	return matchesAny(rule.Verbs, m.Verbs)
}

// providerManagedLabels are labels a managed distribution stamps on the RBAC objects it owns and
// reconciles. Detection is by LABEL ONLY, deliberately: a label key that turns out to be wrong
// simply never matches and costs nothing, whereas a hardcoded role NAME that turns out to be wrong
// either misses the object it was meant for or, worse, downgrades something the customer created.
// No role name is hardcoded anywhere in this file.
//
//   - addonmanager.kubernetes.io/mode: GKE and AKS both run the addon manager and stamp this on
//     the objects it reconciles. This is the load-bearing entry.
//   - kubernetes.io/cluster-service: AKS additionally uses this on its own objects.
//   - eks.amazonaws.com/component: EKS coverage is PARTIAL and this key is unverified against a
//     live cluster. EKS labels its objects inconsistently — some carry this, some carry nothing,
//     and aws-node carries app.kubernetes.io/managed-by: Helm, indistinguishable from a customer
//     release. An EKS object with no label gets no downgrade and will surface as a finding the
//     customer cannot act on. That gap is recorded in the dashboard's BACKLOG rather than closed
//     with a guessed name list.
var providerManagedLabels = []string{
	"addonmanager.kubernetes.io/mode",
	"kubernetes.io/cluster-service",
	"eks.amazonaws.com/component",
}

// isProviderManagedRole reports whether obj is owned by the detected distribution rather than by
// the customer. Gated on the distribution on purpose: a role carrying a provider label on a
// kubeadm cluster is not the provider's, and must keep being reported.
func isProviderManagedRole(obj metav1.Object, distro string) bool {
	if distro != "eks" && distro != "gke" && distro != "aks" {
		return false
	}
	labels := obj.GetLabels()
	for _, key := range providerManagedLabels {
		if _, ok := labels[key]; ok {
			return true
		}
	}
	return false
}

// grantResolver answers "does this RoleRef confer the grant m describes?" over the snapshot's
// (Cluster)Roles — the same tiny slice of an RBAC authorizer podCreateRoleResolver models for
// KG-RB-004, generalized to an arbitrary grantMatcher. It does not model aggregation or
// resourceNames. A roleRef pointing at a role missing from the snapshot resolves to "no grant",
// which is how the API server treats a dangling ref.
type grantResolver struct {
	clusterRoles map[string]rbacv1.ClusterRole
	roles        map[string]rbacv1.Role // key: namespace + "/" + name
}

func newGrantResolver(snap *snapshot.Snapshot) grantResolver {
	r := grantResolver{
		clusterRoles: make(map[string]rbacv1.ClusterRole, len(snap.ClusterRoles)),
		roles:        make(map[string]rbacv1.Role, len(snap.Roles)),
	}
	for _, cr := range snap.ClusterRoles {
		r.clusterRoles[cr.Name] = cr
	}
	for _, role := range snap.Roles {
		r.roles[role.Namespace+"/"+role.Name] = role
	}
	return r
}

// nonSystemSubjects returns the subjects that are not the cluster's own identities — the shape
// isKnownDistroDefaultBinding expects, which requires every one of them to be an expected subject
// of the distribution's bootstrap binding before it grants the downgrade.
func nonSystemSubjects(subjects []rbacv1.Subject) []rbacv1.Subject {
	var out []rbacv1.Subject
	for _, s := range subjects {
		if !isSystemSubject(s) {
			out = append(out, s)
		}
	}
	return out
}

// isKubernetesSystemRole reports whether name is one of the cluster's own control-plane roles.
//
// Deliberately NOT isCustomRoleName, which additionally excludes cluster-admin, admin, edit and
// view. That exclusion exists so KG-RB-002 does not flag those built-in roles' DEFINITIONS as
// suspicious — a different job. The checks in this file report who HOLDS access, and a RoleBinding
// to edit confers its grants for real: excluding it would report the canonical CIS 5.1.13 case
// (edit granting create on serviceaccounts/token inside a namespace) as pass, which is precisely
// the kind of unmeasured claim these checks exist to remove.
func isKubernetesSystemRole(name string) bool {
	return strings.HasPrefix(name, "system:")
}

// grants reports whether ref confers any of the grants matchers describes, and returns the
// resolved role object so the caller can decide whether the distribution owns it.
func (r grantResolver) grants(ref rbacv1.RoleRef, bindingNamespace string, matchers []grantMatcher) (metav1.Object, bool) {
	var rules []rbacv1.PolicyRule
	var meta *metav1.ObjectMeta
	if ref.Kind == "ClusterRole" {
		cr, ok := r.clusterRoles[ref.Name]
		if !ok || isKubernetesSystemRole(cr.Name) {
			return nil, false
		}
		rules, meta = cr.Rules, &cr.ObjectMeta
	} else {
		role, ok := r.roles[bindingNamespace+"/"+ref.Name]
		if !ok || isKubernetesSystemRole(role.Name) {
			return nil, false
		}
		rules, meta = role.Rules, &role.ObjectMeta
	}
	for _, rule := range rules {
		for _, m := range matchers {
			if ruleMatchesGrant(rule, m) {
				return meta, true
			}
		}
	}
	return nil, false
}

// boundGrantResult is the shape every matcher-driven KG-RB check shares. A grant whose role the
// detected distribution owns is DOWNGRADED to "info" rather than dropped: the access is a real
// attack path if the identity is ever widened, it just is not the customer's misconfiguration.
// Hiding it would be the product concealing something it measured; reporting it as the customer's
// fault would be the product blaming them for something they cannot change.
//
// The provider-managed check runs before, and independent of, the non-system-subject filter: the
// entire reason KG-RB-010 misfires on kubelet-api-admin is that GKE binds it to a system identity
// (a kube-system ServiceAccount, or a system:* group) — the exact shape a customer-facing binding
// with only system subjects is normally excluded for. Gating the provider check behind that filter
// would leave the real GKE case unreported instead of downgraded, defeating the point of this
// check. The filter still applies to the customer bucket: a genuinely customer-irrelevant binding
// (only system subjects, role NOT provider-managed) stays unreported, same as before this check.
func boundGrantResult(snap *snapshot.Snapshot, matchers []grantMatcher, failStatus string) Result {
	resolver := newGrantResolver(snap)
	distro := detectedDistribution(snap)
	var customer, provider []string
	nsSet := map[string]bool{}

	// bindingNamespace is the namespace the grant takes effect in — empty for a ClusterRoleBinding,
	// which is cluster-wide. It is deliberately NOT the subject's namespace: the namespace at risk
	// is where the access applies, not where its holder happens to live. KG-RB-013 is
	// namespace-scoped and the dashboard filters on this field, so naming the holder there would
	// hide the finding from the operator responsible for the namespace actually exposed, and show
	// it to one that is not. KG-RB-007 in this same file already follows this convention.
	consider := func(ref, bindingNamespace string, roleObj metav1.Object, subjects []rbacv1.Subject) {
		if isProviderManagedRole(roleObj, distro) {
			provider = append(provider, ref)
			return
		}
		if !hasNonSystemSubject(subjects) {
			return
		}
		customer = append(customer, ref)
		if bindingNamespace != "" {
			nsSet[bindingNamespace] = true
		}
	}

	for _, crb := range snap.ClusterRoleBindings {
		obj, ok := resolver.grants(crb.RoleRef, "", matchers)
		if !ok {
			continue
		}
		// A distribution's own bootstrap binding is not the customer's doing, and since these
		// checks stopped excluding the built-in cluster-admin role they resolve straight through
		// it. kubeadm >=1.29 ships clusterrolebinding/kubeadm:cluster-admins -> cluster-admin,
		// whose subject group carries no system: prefix, so without this every kubeadm cluster
		// would report all six checks against a binding it cannot remove. KG-RB-001 already
		// downgrades exactly this shape; reuse its allowlist rather than inventing a second one.
		if isKnownDistroDefaultBinding(crb, nonSystemSubjects(crb.Subjects), distro) {
			provider = append(provider, "clusterrolebinding/"+crb.Name)
			continue
		}
		consider("clusterrolebinding/"+crb.Name, "", obj, crb.Subjects)
	}
	// A RoleBinding is consulted only for requests inside its own namespace, so it can confer only
	// the namespaced targets. With none of them in play the loop has nothing to find at all.
	if nsMatchers := namespacedMatchers(matchers); len(nsMatchers) > 0 {
		for _, rb := range snap.RoleBindings {
			if obj, ok := resolver.grants(rb.RoleRef, rb.Namespace, nsMatchers); ok {
				consider("rolebinding/"+rb.Namespace+"/"+rb.Name, rb.Namespace, obj, rb.Subjects)
			}
		}
	}

	switch {
	// Provider-owned bindings are NOT folded in here. Once a customer finding exists the result
	// carries the failing status, and a provider binding listed beside it would read as one more
	// object to remediate — which the customer cannot do. The drawer has no way to annotate a
	// single entry, so the honest choice is to surface them only when they stand alone, as "info".
	case len(customer) > 0:
		all := append([]string(nil), customer...)
		sort.Strings(all)
		return Result{Status: failStatus, Namespaces: sortedKeys(nsSet), AffectedResources: all}
	case len(provider) > 0:
		sort.Strings(provider)
		return Result{Status: "info", Namespaces: []string{}, AffectedResources: provider}
	default:
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
}

// ---- KG-RB-010: access to the nodes/proxy sub-resource (CIS 5.1.10) ---------------------------

// nodesProxyMatcher targets the sub-resource CIS 5.1.10 names. get on nodes/proxy is not a
// read-only permission: upstream documents it as authorizing command execution in any container
// running on the node, which is why any verb counts.
var nodesProxyMatcher = grantMatcher{
	APIGroups: []string{""},
	Resources: []string{"nodes/proxy"},
}

type nodesProxyGrantCheck struct{}

func (nodesProxyGrantCheck) ID() string { return "KG-RB-010" }

func (nodesProxyGrantCheck) Run(snap *snapshot.Snapshot) Result {
	// CIS 5.1.10 has no counterpart in the GKE benchmark.
	if benchmarkOmitsControl(snap, "gke") {
		return Result{Status: "na", Namespaces: []string{}, AffectedResources: []string{}}
	}
	return boundGrantResult(snap, []grantMatcher{nodesProxyMatcher}, "warn")
}

// ---- KG-RB-008: bind/escalate/impersonate verb grants (CIS 5.1.8) -----------------------------

// escalationVerbMatchers targets what CIS 5.1.8 calls out: bind and escalate are verbs on RBAC
// objects themselves (rbac.authorization.k8s.io) — granting either lets the holder create a
// binding or a role broader than their own permissions. impersonate is a different axis entirely:
// it is a verb on core-group identities (users, groups, serviceaccounts), letting the holder act
// as any identity it names. Two matchers because CIS bundles three verbs living in two API groups
// under one control.
var escalationVerbMatchers = []grantMatcher{
	{
		APIGroups: []string{"rbac.authorization.k8s.io"},
		Resources: []string{"clusterroles", "clusterrolebindings"},
		Verbs:     []string{"bind", "escalate"},
	},
	{
		APIGroups:  []string{"rbac.authorization.k8s.io"},
		Resources:  []string{"roles", "rolebindings"},
		Verbs:      []string{"bind", "escalate"},
		Namespaced: true,
	},
	{
		APIGroups:  []string{""},
		Resources:  []string{"serviceaccounts"},
		Verbs:      []string{"impersonate"},
		Namespaced: true,
	},
	{
		APIGroups: []string{""},
		Resources: []string{"users", "groups"},
		Verbs:     []string{"impersonate"},
	},
}

type escalationVerbGrantCheck struct{}

func (escalationVerbGrantCheck) ID() string { return "KG-RB-008" }

func (escalationVerbGrantCheck) Run(snap *snapshot.Snapshot) Result {
	return boundGrantResult(snap, escalationVerbMatchers, "fail")
}

// ---- KG-RB-009: create access to PersistentVolumes (CIS 5.1.9) --------------------------------

// persistentVolumeCreateMatcher targets what CIS 5.1.9 names. A PersistentVolume can mount a
// hostPath, so create access to one is a path to the node's filesystem that does not go through
// the pod-security checks at all.
var persistentVolumeCreateMatcher = grantMatcher{
	APIGroups: []string{""},
	Resources: []string{"persistentvolumes"},
	Verbs:     []string{"create"},
}

type persistentVolumeCreateGrantCheck struct{}

func (persistentVolumeCreateGrantCheck) ID() string { return "KG-RB-009" }

func (persistentVolumeCreateGrantCheck) Run(snap *snapshot.Snapshot) Result {
	return boundGrantResult(snap, []grantMatcher{persistentVolumeCreateMatcher}, "warn")
}

// ---- KG-RB-011: approve access to the certificatesigningrequests/approval sub-resource
// (CIS 5.1.11) --------------------------------------------------------------------------------

// csrApprovalMatcher targets the sub-resource CIS 5.1.11 names. Approving a CSR mints a client
// certificate for whatever identity the request names; no Verbs restriction is set because any
// verb on this sub-resource is enough to reach the approve subresource action.
var csrApprovalMatcher = grantMatcher{
	APIGroups: []string{"certificates.k8s.io"},
	Resources: []string{"certificatesigningrequests/approval"},
}

type csrApprovalGrantCheck struct{}

func (csrApprovalGrantCheck) ID() string { return "KG-RB-011" }

func (csrApprovalGrantCheck) Run(snap *snapshot.Snapshot) Result {
	return boundGrantResult(snap, []grantMatcher{csrApprovalMatcher}, "warn")
}

// ---- KG-RB-012: write access to webhook configurations (CIS 5.1.12) ---------------------------

// webhookConfigWriteMatcher targets what CIS 5.1.12 names. Writing a ValidatingWebhookConfiguration
// or MutatingWebhookConfiguration lets the holder point admission at a webhook they control, which
// can rewrite or wave through anything the API server would otherwise enforce.
var webhookConfigWriteMatcher = grantMatcher{
	APIGroups: []string{"admissionregistration.k8s.io"},
	Resources: []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"},
	Verbs:     []string{"create", "update", "patch", "delete"},
}

type webhookConfigWriteGrantCheck struct{}

func (webhookConfigWriteGrantCheck) ID() string { return "KG-RB-012" }

func (webhookConfigWriteGrantCheck) Run(snap *snapshot.Snapshot) Result {
	return boundGrantResult(snap, []grantMatcher{webhookConfigWriteMatcher}, "warn")
}

// ---- KG-RB-013: create access to the serviceaccounts/token sub-resource (CIS 5.1.13) ----------

// tokenCreateMatcher targets the sub-resource CIS 5.1.13 names. Creating a token for a
// ServiceAccount mints a fresh credential for it, independent of any RBAC grant on the
// ServiceAccount object itself — the same privilege-escalation shape as impersonation, reached
// through TokenRequest instead.
var tokenCreateMatcher = grantMatcher{
	APIGroups: []string{""},
	Resources: []string{"serviceaccounts/token"},
	Verbs:     []string{"create"},
	// ServiceAccounts are namespaced, so a RoleBinding genuinely confers this — and that is the
	// canonical shape of the control: a namespace-scoped role that can mint tokens for the
	// ServiceAccounts living beside it.
	Namespaced: true,
}

type tokenCreateGrantCheck struct{}

func (tokenCreateGrantCheck) ID() string { return "KG-RB-013" }

func (tokenCreateGrantCheck) Run(snap *snapshot.Snapshot) Result {
	return boundGrantResult(snap, []grantMatcher{tokenCreateMatcher}, "warn")
}

// ---- KG-RB-007: additional bindings to the system:masters group (CIS 5.1.7) --------------------

// isStockMastersBinding reports whether crb is the cluster-admin -> system:masters
// ClusterRoleBinding that ships with every cluster. Name alone is not enough: a custom binding can
// be named "cluster-admin" and point somewhere else entirely, so the roleRef and the subject list
// must both match.
func isStockMastersBinding(crb rbacv1.ClusterRoleBinding) bool {
	if crb.Name != "cluster-admin" {
		return false
	}
	if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "cluster-admin" {
		return false
	}
	if len(crb.Subjects) != 1 {
		return false
	}
	s := crb.Subjects[0]
	return s.Kind == rbacv1.GroupKind && s.Name == "system:masters"
}

// bindsSystemMasters reports whether any subject is the system:masters GROUP. Kind matters: a User
// that merely carries that name is a different identity and holds none of the group's power.
func bindsSystemMasters(subjects []rbacv1.Subject) bool {
	for _, s := range subjects {
		if s.Kind == rbacv1.GroupKind && s.Name == "system:masters" {
			return true
		}
	}
	return false
}

type systemMastersBindingCheck struct{}

func (systemMastersBindingCheck) ID() string { return "KG-RB-007" }

// Run flags every binding to the system:masters group beyond the stock cluster-admin one. It does
// NOT go through isSystemSubject: that helper treats system:masters as a system identity and skips
// it, which is correct for KG-RB-001 and is exactly the blind spot this check exists to close.
// Changing isSystemSubject instead would have altered a critical check's behavior for free.
//
// The honest limit, which the catalog entry must repeat: the central risk CIS 5.1.7 names is a
// client certificate issued with O=system:masters. A certificate is not an API object — no
// in-cluster agent sees one, on any distribution. This check detects additional BINDINGS to the
// group and nothing else.
func (systemMastersBindingCheck) Run(snap *snapshot.Snapshot) Result {
	// CIS 5.1.7 was removed from the EKS benchmark at 1.7.0 and never existed in the AKS one.
	if benchmarkOmitsControl(snap, "eks", "aks") {
		return Result{Status: "na", Namespaces: []string{}, AffectedResources: []string{}}
	}

	var resources []string
	nsSet := map[string]bool{}

	for _, crb := range snap.ClusterRoleBindings {
		if isStockMastersBinding(crb) || !bindsSystemMasters(crb.Subjects) {
			continue
		}
		resources = append(resources, "clusterrolebinding/"+crb.Name)
	}
	for _, rb := range snap.RoleBindings {
		if !bindsSystemMasters(rb.Subjects) {
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
