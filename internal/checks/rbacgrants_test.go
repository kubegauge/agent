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
				Namespaces:        []string{"ops"},
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
				Namespaces:        []string{"ops"},
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
			name: "a namespaced role granting nodes/proxy warns and names the rolebinding",
			snap: &snapshot.Snapshot{
				Roles: []rbacv1.Role{
					grantRole("team-a", "proxy-role", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
				RoleBindings: []rbacv1.RoleBinding{
					grantRB("team-a", "proxy-binding", "proxy-role", saSubject("team-a", "debugger")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{"team-a"},
				AffectedResources: []string{"rolebinding/team-a/proxy-binding"},
			},
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
			name: "an addon-manager labeled role on GKE is downgraded, not silenced",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{gkeNode()},
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
				Namespaces:        []string{"ops"},
				AffectedResources: []string{"clusterrolebinding/kubelet-api"},
			},
		},
		{
			name: "an unlabeled customer role on GKE still warns",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{gkeNode()},
				ClusterRoles: []rbacv1.ClusterRole{
					grantClusterRole("our-debugger", []string{""}, []string{"nodes/proxy"}, []string{"get"}),
				},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
					grantCRB("our-debugger", "our-debugger", saSubject("ops", "debugger")),
				},
			},
			want: Result{
				Status:            "warn",
				Namespaces:        []string{"ops"},
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
				Namespaces:        []string{"ops"},
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
				Namespaces:        []string{"ops"},
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
				Namespaces:        []string{"storage"},
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
				Namespaces:        []string{"ops"},
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
				Namespaces:        []string{"ops"},
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
				Namespaces:        []string{"ops"},
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
