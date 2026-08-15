// rbacgrants.go implements the KG-RB-007..013 checks: RBAC grants the CIS 5.1.x controls tell you
// to minimize. It is the first code in this repo that inspects PolicyRule.Resources, and therefore
// the first that can see a sub-resource such as "nodes/proxy" at all.
package checks

import (
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"

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

// grants reports whether ref confers ANY of the grants matchers describes. It takes a slice rather
// than a single matcher because CIS 5.1.8 names three verbs living in two different API groups —
// bind and escalate act on RBAC objects, impersonate acts on core identities — and one check has
// to cover both. The single-target checks pass a one-element slice.
func (r grantResolver) grants(ref rbacv1.RoleRef, bindingNamespace string, matchers []grantMatcher) bool {
	rules, name, ok := r.rulesFor(ref, bindingNamespace)
	if !ok || !isCustomRoleName(name) {
		return false
	}
	for _, rule := range rules {
		for _, m := range matchers {
			if ruleMatchesGrant(rule, m) {
				return true
			}
		}
	}
	return false
}

// boundGrantResult is the shape every matcher-driven KG-RB check shares: walk both binding kinds,
// resolve each roleRef, and report the BINDING — the object that creates the access and the object
// an operator edits — whenever a non-system subject holds the grant. Namespaces carries the
// namespaces of the ServiceAccount subjects that hold it, which is what the dashboard's namespace
// filter matches against.
func boundGrantResult(snap *snapshot.Snapshot, matchers []grantMatcher, failStatus string) Result {
	resolver := newGrantResolver(snap)
	var resources []string
	nsSet := map[string]bool{}

	record := func(ref string, subjects []rbacv1.Subject) {
		resources = append(resources, ref)
		for _, s := range subjects {
			if !isSystemSubject(s) && s.Kind == rbacv1.ServiceAccountKind && s.Namespace != "" {
				nsSet[s.Namespace] = true
			}
		}
	}

	for _, crb := range snap.ClusterRoleBindings {
		if !hasNonSystemSubject(crb.Subjects) {
			continue
		}
		if resolver.grants(crb.RoleRef, "", matchers) {
			record("clusterrolebinding/"+crb.Name, crb.Subjects)
		}
	}
	for _, rb := range snap.RoleBindings {
		if !hasNonSystemSubject(rb.Subjects) {
			continue
		}
		if resolver.grants(rb.RoleRef, rb.Namespace, matchers) {
			record("rolebinding/"+rb.Namespace+"/"+rb.Name, rb.Subjects)
		}
	}

	if len(resources) == 0 {
		return Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}
	}
	sort.Strings(resources)
	return Result{Status: failStatus, Namespaces: sortedKeys(nsSet), AffectedResources: resources}
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
