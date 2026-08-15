// rbacgrants_test.go table-tests the KG-RB-007..013 grant checks (rbacgrants.go) against
// hand-built snapshot fixtures, same style as every other file in this package.
package checks

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// grantClusterRole builds a ClusterRole with a single PolicyRule.
func grantClusterRole(name string, apiGroups, resources, verbs []string) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: apiGroups,
			Resources: resources,
			Verbs:     verbs,
		}},
	}
}

// grantCRB builds a ClusterRoleBinding pointing at a ClusterRole.
func grantCRB(name, roleName string, subjects ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName},
		Subjects:   subjects,
	}
}

// saSubject is the common non-system subject used across these fixtures.
func saSubject(namespace, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: name, Namespace: namespace}
}

// grantRole builds a namespaced Role with a single PolicyRule.
func grantRole(namespace, name string, apiGroups, resources, verbs []string) rbacv1.Role {
	return rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: apiGroups,
			Resources: resources,
			Verbs:     verbs,
		}},
	}
}

// grantRB builds a RoleBinding, living in namespace, pointing at a Role by name.
func grantRB(namespace, name, roleName string, subjects ...rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: roleName},
		Subjects:   subjects,
	}
}

// grantRBToClusterRole builds a RoleBinding pointing at a ClusterRole — the standard
// multi-tenancy shape, where one ClusterRole is bound per namespace. The roleRef resolves
// globally, but the binding still only authorizes requests inside its own namespace.
func grantRBToClusterRole(namespace, name, clusterRoleName string, subjects ...rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: clusterRoleName},
		Subjects:   subjects,
	}
}

// gkeNode builds a Node whose providerID makes DetectDistribution report "gke".
func gkeNode() corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "gke-node-1"},
		Spec:       corev1.NodeSpec{ProviderID: "gce://proj/zone/gke-node-1"},
	}
}

// labeledClusterRole builds a ClusterRole carrying labels, for the provider-managed tests.
func labeledClusterRole(name string, labels map[string]string, apiGroups, resources, verbs []string) rbacv1.ClusterRole {
	cr := grantClusterRole(name, apiGroups, resources, verbs)
	cr.Labels = labels
	return cr
}

func TestNodesProxyGrantCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no role grants nodes/proxy",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a bound role granting nodes/proxy warns and names the binding",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("debug-tools", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("debug-tools", "debug-tools", saSubject("ops", "debugger")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/debug-tools"},
			},
		},
		{
			name: "an UNBOUND role granting nodes/proxy is not reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("orphan", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "nodes without the proxy sub-resource does not match",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("node-reader", []string{""}, []string{"nodes"}, []string{"get"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("node-reader", "node-reader", saSubject("ops", "reader")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a wildcard resource subsumes nodes/proxy and is reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("god-mode", []string{"*"}, []string{"*"}, []string{"*"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("god-mode", "god-mode", saSubject("ops", "everything")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/god-mode"},
			},
		},
		{
			name: "a system: role name is excluded even when bound",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("system:kubelet-api-admin", []string{""}, []string{"nodes/proxy"}, []string{"*"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("kubelet-api", "system:kubelet-api-admin", saSubject("kube-system", "kubelet")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a binding whose only subject is a system identity is not reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("proxy-role", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("proxy-binding", "proxy-role",
						rbacv1.Subject{Kind: rbacv1.UserKind, Name: "system:kube-controller-manager"}),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a dangling roleRef resolves to no grant",
			snap: &snapshot.Snapshot{
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("ghost", "does-not-exist", saSubject("ops", "someone")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			// nodes/proxy is cluster-scoped, and RBAC consults a RoleBinding only for requests
			// inside its own namespace — so this binding authorizes nobody, whatever its role's
			// rules say. Reporting it would hand the operator an object to edit for access it does
			// not confer, and the finding would never clear.
			name: "a rolebinding cannot confer the cluster-scoped nodes/proxy and is not reported",
			snap: &snapshot.Snapshot{
				Roles: []rbacv1.Role{
					grantRole("team-a", "proxy-role", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
				RoleBindings: []rbacv1.RoleBinding{
					grantRB("team-a", "proxy-binding", "proxy-role", saSubject("team-a", "debugger")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			// The standard multi-tenancy shape: one wildcard ClusterRole bound per team with a
			// RoleBinding. Before the namespaced-matcher filter this produced simultaneous false
			// findings on four cluster-scoped checks at once.
			name: "a wildcard ClusterRole bound by a RoleBinding confers no cluster-scoped grant",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("team-namespace-admin", []string{"*"}, []string{"*"}, []string{"*"}),
				},
				RoleBindings: []rbacv1.RoleBinding{
					grantRBToClusterRole("team-a", "team-a-admins", "team-namespace-admin", saSubject("team-a", "deployer")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a rolebinding naming a Role that exists only in a different namespace does not resolve",
			snap: &snapshot.Snapshot{
				Roles: []rbacv1.Role{
					grantRole("team-b", "proxy-role", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
				RoleBindings: []rbacv1.RoleBinding{
					grantRB("team-a", "proxy-binding", "proxy-role", saSubject("team-a", "debugger")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			// EKS, not GKE: KG-RB-010 (CIS 5.1.10) has no GKE counterpart and now reports "na"
			// unconditionally there (see TestNodesProxyNaOnGke), which would make gkeNode() unable
			// to reach the provider-managed downgrade this subtest exercises at all. EKS isn't
			// na-gated for this check, and isProviderManagedRole treats the addon-manager label the
			// same regardless of which of eks/gke/aks triggered it.
			name: "an addon-manager labeled role on EKS is downgraded, not silenced",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{eksNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					labeledClusterRole("kubelet-api-admin",
						map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
						[]string{""}, []string{"nodes/proxy"}, []string{"*"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("kubelet-api", "kubelet-api-admin", saSubject("kube-system", "kubelet")),
				},
			},
			want: Result{
				Status:            "info",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/kubelet-api"},
			},
		},
		{
			name: "the same labeled role on a kubeadm cluster is NOT downgraded",
			snap: &snapshot.Snapshot{
				KubeadmConfigMapFound: true,
				ClusterRoles: []rbacv1.ClusterRole{
					labeledClusterRole("kubelet-api-admin",
						map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
						[]string{""}, []string{"nodes/proxy"}, []string{"*"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("kubelet-api", "kubelet-api-admin", saSubject("ops", "someone")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/kubelet-api"},
			},
		},
		{
			// EKS, not GKE — same reason as above: gkeNode() would now short-circuit to "na" before
			// ever reaching the warn/downgrade logic this subtest is pinning.
			name: "an unlabeled customer role on EKS still warns",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{eksNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("our-debugger", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("our-debugger", "our-debugger", saSubject("ops", "debugger")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/our-debugger"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (nodesProxyGrantCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEscalationVerbGrantCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no role grants bind, escalate or impersonate",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a bound role granting escalate on clusterroles fails and names the binding",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("escalator", []string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("escalator", "escalator", saSubject("ops", "operator")),
				},
			},
			want: Result{
				Status:            "fail",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/escalator"},
			},
		},
		{
			name: "an UNBOUND role granting escalate is not reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("orphan-escalator", []string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"}),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "get/list on the same RBAC resources does not match",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("rbac-reader",
						[]string{"rbac.authorization.k8s.io"},
						[]string{"roles", "clusterroles", "rolebindings", "clusterrolebindings"},
						[]string{"get", "list"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("rbac-reader", "rbac-reader", saSubject("ops", "reader")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "an addon-manager labeled role on GKE is downgraded, not silenced",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{gkeNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					labeledClusterRole("escalator-managed",
						map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
						[]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("escalator-managed", "escalator-managed", saSubject("kube-system", "controller")),
				},
			},
			want: Result{
				Status:            "info",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/escalator-managed"},
			},
		},
		{
			name: "impersonate on users and escalate on clusterroles are both reported, proving both matchers are consulted",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("impersonator", []string{""}, []string{"users"}, []string{"impersonate"}),
					grantClusterRole("escalator-two", []string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("impersonator-binding", "impersonator", saSubject("ops", "impersonator")),
					grantCRB("escalator-binding", "escalator-two", saSubject("ops", "escalator")),
				},
			},
			want: Result{
				Status:            "fail",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/escalator-binding", "clusterrolebinding/impersonator-binding"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (escalationVerbGrantCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPersistentVolumeCreateGrantCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no role grants create on persistentvolumes",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a bound role granting create on persistentvolumes warns and names the binding",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("pv-creator", []string{""}, []string{"persistentvolumes"}, []string{"create"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("pv-creator", "pv-creator", saSubject("storage", "provisioner")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/pv-creator"},
			},
		},
		{
			name: "an UNBOUND role granting create on persistentvolumes is not reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("orphan-pv-creator", []string{""}, []string{"persistentvolumes"}, []string{"create"}),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "create on persistentvolumeclaims does not match",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("pvc-creator", []string{""}, []string{"persistentvolumeclaims"}, []string{"create"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("pvc-creator", "pvc-creator", saSubject("storage", "claimant")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "an addon-manager labeled role on GKE is downgraded, not silenced",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{gkeNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					labeledClusterRole("pv-creator-managed",
						map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
						[]string{""}, []string{"persistentvolumes"}, []string{"create"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("pv-creator-managed", "pv-creator-managed", saSubject("kube-system", "provisioner")),
				},
			},
			want: Result{
				Status:            "info",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/pv-creator-managed"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (persistentVolumeCreateGrantCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCsrApprovalGrantCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no role grants access to certificatesigningrequests/approval",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a bound role granting update on certificatesigningrequests/approval warns and names the binding",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("csr-approver", []string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("csr-approver", "csr-approver", saSubject("ops", "approver")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/csr-approver"},
			},
		},
		{
			name: "an UNBOUND role granting the approval sub-resource is not reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("orphan-csr-approver", []string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "certificatesigningrequests without the approval sub-resource does not match",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("csr-reader", []string{"certificates.k8s.io"}, []string{"certificatesigningrequests"}, []string{"get", "list", "update"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("csr-reader", "csr-reader", saSubject("ops", "reader")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "an addon-manager labeled role on GKE is downgraded, not silenced",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{gkeNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					labeledClusterRole("csr-approver-managed",
						map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
						[]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("csr-approver-managed", "csr-approver-managed", saSubject("kube-system", "controller")),
				},
			},
			want: Result{
				Status:            "info",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/csr-approver-managed"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (csrApprovalGrantCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWebhookConfigWriteGrantCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no role grants write access to webhook configurations",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a bound role granting create on validatingwebhookconfigurations warns and names the binding",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("webhook-writer", []string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"create"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("webhook-writer", "webhook-writer", saSubject("ops", "operator")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/webhook-writer"},
			},
		},
		{
			name: "an UNBOUND role granting write access to webhook configurations is not reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("orphan-webhook-writer", []string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"update"}),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "get/list/watch on the same resources does not match",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("webhook-reader",
						[]string{"admissionregistration.k8s.io"},
						[]string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"},
						[]string{"get", "list", "watch"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("webhook-reader", "webhook-reader", saSubject("ops", "reader")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "an addon-manager labeled role on GKE is downgraded, not silenced",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{gkeNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					labeledClusterRole("webhook-writer-managed",
						map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
						[]string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"patch"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("webhook-writer-managed", "webhook-writer-managed", saSubject("kube-system", "controller")),
				},
			},
			want: Result{
				Status:            "info",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/webhook-writer-managed"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (webhookConfigWriteGrantCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSystemMastersBindingCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "the stock cluster-admin binding alone passes",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("cluster-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "an additional binding to the group fails",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("cluster-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
				grantCRB("ops-masters", "view", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
			}},
			want: Result{
				Status:            "fail",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/ops-masters"},
			},
		},
		{
			name: "a RoleBinding to the group fails too",
			snap: &snapshot.Snapshot{RoleBindings: []rbacv1.RoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "masters-in-ns", Namespace: "payments"},
				RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "editor"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:masters"}},
			}}},
			want: Result{
				Status:            "fail",
				Namespaces:        []string{"payments"},
				AffectedResources: []string{"rolebinding/payments/masters-in-ns"},
			},
		},
		{
			name: "a binding named cluster-admin but pointing elsewhere is not the stock one",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				grantCRB("cluster-admin", "view", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
			}},
			want: Result{
				Status:            "fail",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/cluster-admin"},
			},
		},
		{
			name: "a User merely named like the group is a different identity",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				grantCRB("impostor", "view", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "system:masters"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "no binding to the group at all passes",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (systemMastersBindingCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestBenchmarkOmitsControlGuard pins the false-na trap directly: a plain kubeadm cluster whose
// nodes carry an EKS-shaped providerID (kubeadm bootstrapped on raw EC2 instances) must still
// evaluate KG-RB-007, because report.DetectDistribution resolves aws:// to "eks" before it ever
// looks at KubeadmConfigMapFound. Gating benchmarkOmitsControl on distribution alone would report
// "na" to a cluster the control genuinely applies to.
func TestBenchmarkOmitsControlGuard(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want string
	}{
		{
			name: "KG-RB-007 is na on a real EKS cluster",
			snap: &snapshot.Snapshot{Nodes: []corev1.Node{eksNode()}},
			want: "na",
		},
		{
			name: "KG-RB-007 still evaluates on kubeadm running on EC2",
			snap: &snapshot.Snapshot{
				Nodes:                 []corev1.Node{eksNode()},
				KubeadmConfigMapFound: true,
			},
			want: "pass",
		},
		{
			name: "KG-RB-007 evaluates normally on GKE, where the control exists",
			snap: &snapshot.Snapshot{Nodes: []corev1.Node{gkeNode()}},
			want: "pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (systemMastersBindingCheck{}).Run(tt.snap).Status; got != tt.want {
				t.Errorf("Status = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNodesProxyNaOnGke covers KG-RB-010's own gate: "na" on GKE (CIS 5.1.10 has no GKE
// counterpart), but still evaluated on a kubeadm cluster running on GCE VMs, which detects as
// "gke" the same way kubeadm-on-EC2 detects as "eks".
func TestNodesProxyNaOnGke(t *testing.T) {
	naSnap := &snapshot.Snapshot{Nodes: []corev1.Node{gkeNode()}}
	if got := (nodesProxyGrantCheck{}).Run(naSnap).Status; got != "na" {
		t.Errorf("on GKE, Status = %q, want \"na\"", got)
	}
	kubeadmOnGce := &snapshot.Snapshot{
		Nodes:                 []corev1.Node{gkeNode()},
		KubeadmConfigMapFound: true,
	}
	if got := (nodesProxyGrantCheck{}).Run(kubeadmOnGce).Status; got != "pass" {
		t.Errorf("on kubeadm-on-GCE, Status = %q, want \"pass\"", got)
	}
}

func TestTokenCreateGrantCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no role grants create on serviceaccounts/token",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "a bound role granting create on serviceaccounts/token warns and names the binding",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("token-creator", []string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("token-creator", "token-creator", saSubject("ops", "minter")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/token-creator"},
			},
		},
		{
			name: "an UNBOUND role granting create on serviceaccounts/token is not reported",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("orphan-token-creator", []string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "serviceaccounts without the token sub-resource does not match",
			snap: &snapshot.Snapshot{
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("sa-creator", []string{""}, []string{"serviceaccounts"}, []string{"create"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("sa-creator", "sa-creator", saSubject("ops", "creator")),
				},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "an addon-manager labeled role on GKE is downgraded, not silenced",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{gkeNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					labeledClusterRole("token-creator-managed",
						map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
						[]string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("token-creator-managed", "token-creator-managed", saSubject("kube-system", "controller")),
				},
			},
			want: Result{
				Status:            "info",
				Namespaces:        []string{},
				AffectedResources: []string{"clusterrolebinding/token-creator-managed"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (tokenCreateGrantCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRoleBindingScopeAndBuiltInRoles covers the four rules the whole-branch review established:
// a RoleBinding confers only namespaced targets, a binding to a built-in role is still access,
// Namespaces names where the grant applies rather than where its holder lives, and a
// provider-owned binding is not listed beside a customer finding it cannot explain.
func TestRoleBindingScopeAndBuiltInRoles(t *testing.T) {
	t.Run("the wildcard ClusterRole a RoleBinding cannot use for nodes/proxy IS reported for the namespaced token grant", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			ClusterRoles: []rbacv1.ClusterRole{
				grantClusterRole("team-namespace-admin", []string{"*"}, []string{"*"}, []string{"*"}),
			},
			RoleBindings: []rbacv1.RoleBinding{
				grantRBToClusterRole("team-a", "team-a-admins", "team-namespace-admin", saSubject("team-a", "deployer")),
			},
		}
		if got := (nodesProxyGrantCheck{}).Run(snap).Status; got != "pass" {
			t.Errorf("KG-RB-010 on a RoleBinding: got %q, want \"pass\" (nodes/proxy is cluster-scoped)", got)
		}
		want := Result{
			Status:            "warn",
			Namespaces:        []string{"team-a"},
			AffectedResources: []string{"rolebinding/team-a/team-a-admins"},
		}
		if got := (tokenCreateGrantCheck{}).Run(snap); !reflect.DeepEqual(got, want) {
			t.Errorf("KG-RB-013 on the same binding: got %+v, want %+v", got, want)
		}
	})

	t.Run("a RoleBinding to the built-in edit role is access and is reported", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			ClusterRoles: []rbacv1.ClusterRole{
				grantClusterRole("edit", []string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
			},
			RoleBindings: []rbacv1.RoleBinding{
				grantRBToClusterRole("payments", "devs", "edit", saSubject("payments", "app")),
			},
		}
		want := Result{
			Status:            "warn",
			Namespaces:        []string{"payments"},
			AffectedResources: []string{"rolebinding/payments/devs"},
		}
		if got := (tokenCreateGrantCheck{}).Run(snap); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v — a binding to edit confers the grant for real", got, want)
		}
	})

	t.Run("a system: role stays excluded even when bound", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			ClusterRoles: []rbacv1.ClusterRole{
				grantClusterRole("system:controller:token-minter", []string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
			},
			RoleBindings: []rbacv1.RoleBinding{
				grantRBToClusterRole("kube-system", "minter", "system:controller:token-minter", saSubject("payments", "app")),
			},
		}
		if got := (tokenCreateGrantCheck{}).Run(snap).Status; got != "pass" {
			t.Errorf("got %q, want \"pass\" — the cluster's own control-plane roles stay out", got)
		}
	})

	t.Run("Namespaces names where the grant applies, not where its holder lives", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			Roles: []rbacv1.Role{
				grantRole("frontend", "token-minter", []string{""}, []string{"serviceaccounts/token"}, []string{"create"}),
			},
			RoleBindings: []rbacv1.RoleBinding{
				grantRB("frontend", "minter", "token-minter", saSubject("ci-cd", "deployer")),
			},
		}
		got := (tokenCreateGrantCheck{}).Run(snap)
		want := Result{
			Status:            "warn",
			Namespaces:        []string{"frontend"},
			AffectedResources: []string{"rolebinding/frontend/minter"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v — frontend is the namespace exposed; ci-cd merely holds the grant", got, want)
		}
	})

	// eksNode, not gkeNode: KG-RB-010 reports na on GKE because the CIS GKE Benchmark has no
	// counterpart to 5.1.10, so the downgrade path is unreachable there by design.
	t.Run("a provider binding is not listed beside a customer finding", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			Nodes: []corev1.Node{eksNode()},
			ClusterRoles: []rbacv1.ClusterRole{
				labeledClusterRole("provider-proxy",
					map[string]string{"addonmanager.kubernetes.io/mode": "Reconcile"},
					[]string{""}, []string{"nodes/proxy"}, []string{"*"}),
				grantClusterRole("our-debugger", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				grantCRB("provider-proxy", "provider-proxy", saSubject("kube-system", "addon")),
				grantCRB("our-debugger", "our-debugger", saSubject("ops", "debugger")),
			},
		}
		got := (nodesProxyGrantCheck{}).Run(snap)
		want := Result{
			Status:            "warn",
			Namespaces:        []string{},
			AffectedResources: []string{"clusterrolebinding/our-debugger"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v — the provider binding must not be handed over as something to remediate", got, want)
		}
	})
}
