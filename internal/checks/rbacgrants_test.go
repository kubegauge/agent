// rbacgrants_test.go table-tests the KG-RB-007..013 grant checks (rbacgrants.go) against
// hand-built snapshot fixtures, same style as every other file in this package.
package checks

import (
	"reflect"
	"testing"

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
