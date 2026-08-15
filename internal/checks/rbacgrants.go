// rbacgrants.go implements the KG-RB-007..013 checks: RBAC grants the CIS 5.1.x controls tell you
// to minimize. It is the first code in this repo that inspects PolicyRule.Resources, and therefore
// the first that can see a sub-resource such as "nodes/proxy" at all.
package checks

import (
	"sort"

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

// rulesFor resolves ref (from a binding living in bindingNamespace; "" for a ClusterRoleBinding)
// to its rules, and reports the resolved role's name plus whether it was found.
func (r grantResolver) rulesFor(ref rbacv1.RoleRef, bindingNamespace string) ([]rbacv1.PolicyRule, string, bool) {
	if ref.Kind == "ClusterRole" {
		cr, ok := r.clusterRoles[ref.Name]
		return cr.Rules, cr.Name, ok
	}
	role, ok := r.roles[bindingNamespace+"/"+ref.Name]
	return role.Rules, role.Name, ok
}

// grants reports whether ref confers any of the grants matchers describes, and returns the
// resolved role object so the caller can decide whether the distribution owns it.
func (r grantResolver) grants(ref rbacv1.RoleRef, bindingNamespace string, matchers []grantMatcher) (metav1.Object, bool) {
	var rules []rbacv1.PolicyRule
	var meta *metav1.ObjectMeta
	if ref.Kind == "ClusterRole" {
		cr, ok := r.clusterRoles[ref.Name]
		if !ok || !isCustomRoleName(cr.Name) {
			return nil, false
		}
		rules, meta = cr.Rules, &cr.ObjectMeta
	} else {
		role, ok := r.roles[bindingNamespace+"/"+ref.Name]
		if !ok || !isCustomRoleName(role.Name) {
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

	consider := func(ref string, roleObj metav1.Object, subjects []rbacv1.Subject) {
		if isProviderManagedRole(roleObj, distro) {
			provider = append(provider, ref)
			return
		}
		if !hasNonSystemSubject(subjects) {
			return
		}
		customer = append(customer, ref)
		for _, s := range subjects {
			if !isSystemSubject(s) && s.Kind == rbacv1.ServiceAccountKind && s.Namespace != "" {
				nsSet[s.Namespace] = true
			}
		}
	}

	for _, crb := range snap.ClusterRoleBindings {
		if obj, ok := resolver.grants(crb.RoleRef, "", matchers); ok {
			consider("clusterrolebinding/"+crb.Name, obj, crb.Subjects)
		}
	}
	for _, rb := range snap.RoleBindings {
		if obj, ok := resolver.grants(rb.RoleRef, rb.Namespace, matchers); ok {
			consider("rolebinding/"+rb.Namespace+"/"+rb.Name, obj, rb.Subjects)
		}
	}

	switch {
	case len(customer) > 0:
		all := append(append([]string(nil), customer...), provider...)
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
	return boundGrantResult(snap, []grantMatcher{nodesProxyMatcher}, "warn")
}
