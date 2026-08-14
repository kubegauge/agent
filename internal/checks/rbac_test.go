// rbac_test.go table-tests the KG-RB-* checks and RbacFindings (rbac.go) against hand-built
// snapshot fixtures.
package checks

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

func clusterAdminCRB(name string, subjects ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   subjects,
	}
}

func TestClusterAdminBindingCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "default cluster-admin -> system:masters binding is excluded",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("cluster-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "cluster-admin bound to a workload ServiceAccount fails",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("jenkins-admin", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "jenkins", Namespace: "ci-cd"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{"ci-cd"}, AffectedResources: []string{"clusterrolebinding/jenkins-admin"}},
		},
		{
			name: "cluster-admin bound to a ServiceAccount in a system namespace is excluded",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("system-binding", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "coredns", Namespace: "kube-system"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "cluster-admin bound to a system:-prefixed User is excluded",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("kubelet-binding", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "system:kube-scheduler"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kubeadm's own default cluster-admin binding for its bootstrap group warns, not fails",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("kubeadm:cluster-admins", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "kubeadm:cluster-admins"}),
			}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"clusterrolebinding/kubeadm:cluster-admins"}},
		},
		{
			name: "the same kubeadm bootstrap group granted via a differently-named custom binding still fails",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("ops-team-admin-binding", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "kubeadm:cluster-admins"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"clusterrolebinding/ops-team-admin-binding"}},
		},
		{
			name: "a genuine custom cluster-admin binding still fails the whole check, with the known kubeadm default still listed alongside it",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("kubeadm:cluster-admins", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "kubeadm:cluster-admins"}),
				clusterAdminCRB("jenkins-admin", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "jenkins", Namespace: "ci-cd"}),
			}},
			want: Result{
				Status:            "fail",
				Namespaces:        []string{"ci-cd"},
				AffectedResources: []string{"clusterrolebinding/jenkins-admin", "clusterrolebinding/kubeadm:cluster-admins"},
			},
		},
		{
			name: "binding to a different ClusterRole is not this check's concern",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "view-binding"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "reader", Namespace: "default"}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "EKS addon-manager binding warns instead of failing",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("eks:addon-cluster-admin", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "eks:addon-manager"}),
			}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"clusterrolebinding/eks:addon-cluster-admin"}},
		},
		{
			name: "a provider binding name carrying an unexpected extra subject still fails",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("eks:addon-cluster-admin",
					rbacv1.Subject{Kind: rbacv1.UserKind, Name: "eks:addon-manager"},
					rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "jenkins", Namespace: "ci-cd"},
				),
			}},
			want: Result{Status: "fail", Namespaces: []string{"ci-cd"}, AffectedResources: []string{"clusterrolebinding/eks:addon-cluster-admin"}},
		},
		{
			name: "the AKS user granted through a differently-named custom binding still fails",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("ops-shortcut", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "clusterAdmin"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"clusterrolebinding/ops-shortcut"}},
		},
		{
			name: "a Group subject sharing the EKS user name does not get the downgrade",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("eks:addon-cluster-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "eks:addon-manager"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"clusterrolebinding/eks:addon-cluster-admin"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (clusterAdminBindingCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWildcardRoleCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "custom ClusterRole with wildcard verbs fails",
			snap: &snapshot.Snapshot{ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "prometheus-operator"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
			}}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"clusterrole/prometheus-operator"}},
		},
		{
			name: "custom ClusterRole with wildcard apiGroups fails",
			snap: &snapshot.Snapshot{ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "broad-reader"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list"}}},
			}}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"clusterrole/broad-reader"}},
		},
		{
			name: "built-in cluster-admin role is excluded (its bindings are KG-RB-001's concern)",
			snap: &snapshot.Snapshot{ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "system:-prefixed role is excluded",
			snap: &snapshot.Snapshot{ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "system:controller:deployment-controller"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Verbs: []string{"*"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "namespaced Role with wildcard verbs fails and reports its namespace",
			snap: &snapshot.Snapshot{Roles: []rbacv1.Role{{
				ObjectMeta: metav1.ObjectMeta{Name: "everything", Namespace: "monitoring"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
			}}},
			want: Result{Status: "fail", Namespaces: []string{"monitoring"}, AffectedResources: []string{"role/monitoring/everything"}},
		},
		{
			name: "role with explicit, non-wildcard verbs passes",
			snap: &snapshot.Snapshot{ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "reader"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (wildcardRoleCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSecretsAccessRoleCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "custom role with get/list on secrets fails",
			snap: &snapshot.Snapshot{Roles: []rbacv1.Role{{
				ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}},
			}}},
			want: Result{Status: "fail", Namespaces: []string{"monitoring"}, AffectedResources: []string{"role/monitoring/grafana"}},
		},
		{
			name: "built-in view role is excluded",
			snap: &snapshot.Snapshot{ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "view"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "role touching a different resource passes",
			snap: &snapshot.Snapshot{Roles: []rbacv1.Role{{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-reader", Namespace: "monitoring"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "role with only create/delete/update on secrets passes (no read verb)",
			snap: &snapshot.Snapshot{Roles: []rbacv1.Role{{
				ObjectMeta: metav1.ObjectMeta{Name: "secret-writer", Namespace: "monitoring"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "update", "delete"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (secretsAccessRoleCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func serviceAccount(namespace, name string, automount *bool) corev1.ServiceAccount {
	return corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: name, Namespace: namespace},
		AutomountServiceAccountToken: automount,
	}
}

func TestAutomountDefaultSACheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "default SA with unset automount (effective true) warns",
			snap: &snapshot.Snapshot{ServiceAccounts: []corev1.ServiceAccount{serviceAccount("frontend", "default", nil)}},
			want: Result{Status: "warn", Namespaces: []string{"frontend"}, AffectedResources: []string{"sa/frontend/default"}},
		},
		{
			name: "default SA with automount explicitly false passes",
			snap: &snapshot.Snapshot{ServiceAccounts: []corev1.ServiceAccount{serviceAccount("payments", "default", boolPtr(false))}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "default SA in kube-system is excluded",
			snap: &snapshot.Snapshot{ServiceAccounts: []corev1.ServiceAccount{serviceAccount("kube-system", "default", nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "non-default ServiceAccount is not this check's concern",
			snap: &snapshot.Snapshot{ServiceAccounts: []corev1.ServiceAccount{serviceAccount("frontend", "custom-sa", nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (automountDefaultSACheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRbacFindings(t *testing.T) {
	t.Run("cluster-admin bound to a workload SA yields a critical finding", func(t *testing.T) {
		snap := &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			clusterAdminCRB("jenkins-admin", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "jenkins", Namespace: "ci-cd"}),
		}}
		got := RbacFindings(snap)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
		}
		want := report.RbacFinding{
			ID: "RB-F-001", Subject: "jenkins", SubjectKind: "ServiceAccount",
			Binding: "jenkins-admin", BindingKind: "ClusterRoleBinding", Role: "cluster-admin",
			Risk:   "critical",
			Reason: "Grants cluster-admin (full control of the cluster) to a subject outside the expected system identities.",
		}
		if got[0] != want {
			t.Errorf("finding = %+v, want %+v", got[0], want)
		}
	})

	t.Run("kubeadm's default cluster-admin binding yields a medium-risk finding, not critical", func(t *testing.T) {
		snap := &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			clusterAdminCRB("kubeadm:cluster-admins", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "kubeadm:cluster-admins"}),
		}}
		got := RbacFindings(snap)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
		}
		if got[0].Risk != "medium" {
			t.Errorf("Risk = %q, want medium", got[0].Risk)
		}
		if got[0].Reason != distroDefaultBindingReason("kubeadm:cluster-admins") {
			t.Errorf("Reason = %q, want the known-default binding reason", got[0].Reason)
		}
	})

	t.Run("default cluster-admin -> system:masters yields no finding", func(t *testing.T) {
		snap := &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			clusterAdminCRB("cluster-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
		}}
		got := RbacFindings(snap)
		if len(got) != 0 {
			t.Errorf("expected no findings, got %+v", got)
		}
	})

	t.Run("binding to a custom wildcard ClusterRole yields a high-risk finding", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "broad-reader"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Verbs: []string{"*"}}},
			}},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "broad-reader-binding"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "broad-reader"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			}},
		}
		got := RbacFindings(snap)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
		}
		if got[0].Risk != "high" || got[0].Role != "broad-reader" || got[0].Subject != "alice" {
			t.Errorf("unexpected finding: %+v", got[0])
		}
	})

	t.Run("binding to a custom secrets-reading Role yields a finding scoped to its namespace", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			Roles: []rbacv1.Role{{
				ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "monitoring"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}},
			}},
			RoleBindings: []rbacv1.RoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "grafana-binding", Namespace: "monitoring"},
				RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "grafana"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "grafana", Namespace: "monitoring"}},
			}},
		}
		got := RbacFindings(snap)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
		}
		if got[0].Risk != "high" || got[0].Role != "grafana" || got[0].BindingKind != "RoleBinding" {
			t.Errorf("unexpected finding: %+v", got[0])
		}
		if got[0].Namespace != "monitoring" {
			t.Errorf("Namespace = %q, want monitoring — a RoleBinding finding without it cannot be filtered by namespace downstream", got[0].Namespace)
		}
	})

	// A RoleBinding may point at a ClusterRole, and then there is no role namespace to fall back
	// on. The binding's own namespace is still the boundary of the grant, and still what must be
	// reported.
	t.Run("a RoleBinding pointing at a ClusterRole still carries the binding's namespace", func(t *testing.T) {
		snap := &snapshot.Snapshot{
			ClusterRoles: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "broad-reader"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Verbs: []string{"*"}}},
			}},
			RoleBindings: []rbacv1.RoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "payments-broad", Namespace: "payments"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "broad-reader"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
			}},
		}
		got := RbacFindings(snap)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
		}
		if got[0].BindingKind != "RoleBinding" || got[0].Namespace != "payments" {
			t.Errorf("BindingKind/Namespace = %q/%q, want RoleBinding/payments", got[0].BindingKind, got[0].Namespace)
		}
	})

	// A ClusterRoleBinding is cluster-scoped: an empty Namespace is what tells the dashboard the
	// grant crosses every namespace. The subject here is a ServiceAccount living in ci-cd, so this
	// also pins that the subject's namespace is not borrowed as the finding's.
	t.Run("a ClusterRoleBinding finding carries no namespace", func(t *testing.T) {
		snap := &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			clusterAdminCRB("jenkins-admin", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "jenkins", Namespace: "ci-cd"}),
		}}
		got := RbacFindings(snap)
		if len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
		}
		if got[0].Namespace != "" {
			t.Errorf("Namespace = %q, want empty — a cluster-wide grant hidden behind a namespace filter is a false green", got[0].Namespace)
		}
	})

	t.Run("automount is never duplicated into rbacFindings", func(t *testing.T) {
		snap := &snapshot.Snapshot{ServiceAccounts: []corev1.ServiceAccount{serviceAccount("frontend", "default", nil)}}
		got := RbacFindings(snap)
		if len(got) != 0 {
			t.Errorf("expected automount to produce no RbacFinding entries, got %+v", got)
		}
	})

	t.Run("ids are assigned deterministically by (bindingKind, binding, subject) order", func(t *testing.T) {
		snap := &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			clusterAdminCRB("z-binding", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "z-sa", Namespace: "ci-cd"}),
			clusterAdminCRB("a-binding", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "a-sa", Namespace: "ci-cd"}),
		}}
		got := RbacFindings(snap)
		if len(got) != 2 {
			t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
		}
		if got[0].ID != "RB-F-001" || got[0].Binding != "a-binding" {
			t.Errorf("expected a-binding first with id RB-F-001, got %+v", got[0])
		}
		if got[1].ID != "RB-F-002" || got[1].Binding != "z-binding" {
			t.Errorf("expected z-binding second with id RB-F-002, got %+v", got[1])
		}
	})

	t.Run("never returns nil", func(t *testing.T) {
		got := RbacFindings(&snapshot.Snapshot{})
		if got == nil {
			t.Error("expected a non-nil empty slice, got nil")
		}
	})
}

// systemAuthenticatedCRB builds a ClusterRoleBinding granting roleName to the
// system:authenticated group, with optional labels.
func systemAuthenticatedCRB(name, roleName string, labels map[string]string) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:authenticated"}},
	}
}

var rbacBootstrapLabels = map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}

func TestSystemAuthenticatedBindingCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "empty snapshot passes",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "only the API server's own bootstrap bindings pass",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				systemAuthenticatedCRB("system:basic-user", "system:basic-user", rbacBootstrapLabels),
				systemAuthenticatedCRB("system:discovery", "system:discovery", rbacBootstrapLabels),
				systemAuthenticatedCRB("system:public-info-viewer", "system:public-info-viewer", rbacBootstrapLabels),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "custom ClusterRoleBinding to system:authenticated fails",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				systemAuthenticatedCRB("system:basic-user", "system:basic-user", rbacBootstrapLabels),
				systemAuthenticatedCRB("give-everyone-view", "view", nil),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"clusterrolebinding/give-everyone-view"}},
		},
		{
			name: "default-named binding without the bootstrap label fails (manually recreated, not the API server's)",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				systemAuthenticatedCRB("system:basic-user", "system:basic-user", nil),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"clusterrolebinding/system:basic-user"}},
		},
		{
			name: "namespaced RoleBinding to system:authenticated fails with its namespace listed",
			snap: &snapshot.Snapshot{RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "everyone-can-read", Namespace: "prod"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "reader"},
					Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:authenticated"}},
				},
			}},
			want: Result{Status: "fail", Namespaces: []string{"prod"}, AffectedResources: []string{"rolebinding/prod/everyone-can-read"}},
		},
		{
			name: "bindings to other groups are ignored",
			snap: &snapshot.Snapshot{ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				clusterAdminCRB("ops-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "ops-team"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := systemAuthenticatedBindingCheck{}.Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// podCreateRole builds a namespaced Role granting create on pods.
func podCreateRole(ns, name string) rbacv1.Role {
	return rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
		},
	}
}

// podMountingSecret builds a Pod that mounts a Secret as a volume. The agent never lists Secrets
// (see secretBearingNamespaces in rbac.go), so a reference like this one is what tells KG-RB-004
// that a namespace holds one.
func podMountingSecret(ns, name string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name:         "creds",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "db-password"}},
			}},
		},
	}
}

// TestSecretBearingNamespaces pins the reference shapes that count as evidence of a Secret, and
// the ones that must not: the agent has no secrets grant, so this inference is all KG-RB-004 has.
func TestSecretBearingNamespaces(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want []string
	}{
		{
			name: "empty snapshot yields nothing",
			snap: &snapshot.Snapshot{},
			want: []string{},
		},
		{
			name: "secret volume on a live pod",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podMountingSecret("payments", "api-0")}},
			want: []string{"payments"},
		},
		{
			name: "projected secret volume",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "payments"},
				Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
					Name: "projected",
					VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
						Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{}}},
					}},
				}}},
			}}},
			want: []string{"payments"},
		},
		{
			name: "secret consumed as an env var in a Deployment template",
			snap: &snapshot.Snapshot{Deployments: []appsv1.Deployment{{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "frontend"},
				Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "web",
						Env: []corev1.EnvVar{{
							Name:      "DB_PASSWORD",
							ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{}},
						}},
					}},
				}}},
			}}},
			want: []string{"frontend"},
		},
		{
			name: "imagePullSecrets count",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "payments"},
				Spec:       corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "registry"}}},
			}}},
			want: []string{"payments"},
		},
		{
			name: "ServiceAccount and Ingress TLS references count",
			snap: &snapshot.Snapshot{
				ServiceAccounts: []corev1.ServiceAccount{{
					ObjectMeta:       metav1.ObjectMeta{Name: "deployer", Namespace: "ci"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "registry"}},
				}},
				Ingresses: []networkingv1.Ingress{{
					ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "frontend"},
					Spec:       networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "web-tls"}}},
				}},
			},
			want: []string{"ci", "frontend"},
		},
		{
			name: "system namespaces are excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podMountingSecret("kube-system", "kube-dns")}},
			want: []string{},
		},
		{
			name: "a pod that references no secret is not evidence",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "payments"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
			}}},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedKeys(secretBearingNamespaces(tt.snap))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPodCreateInSecretNamespacesCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "empty snapshot passes",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "RoleBinding granting create pods in a namespace with secrets warns",
			snap: &snapshot.Snapshot{
				Pods:  []corev1.Pod{podMountingSecret("payments", "api-0")},
				Roles: []rbacv1.Role{podCreateRole("payments", "deployer")},
				RoleBindings: []rbacv1.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: "ci-deployer", Namespace: "payments"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "deployer"},
					Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "ci", Namespace: "ci-cd"}},
				}},
			},
			want: Result{Status: "warn", Namespaces: []string{"payments"}, AffectedResources: []string{"rolebinding/payments/ci-deployer"}},
		},
		{
			name: "same RoleBinding in a namespace without secrets passes",
			snap: &snapshot.Snapshot{
				Roles: []rbacv1.Role{podCreateRole("payments", "deployer")},
				RoleBindings: []rbacv1.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: "ci-deployer", Namespace: "payments"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "deployer"},
					Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "ci", Namespace: "ci-cd"}},
				}},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "ClusterRoleBinding granting create pods warns for every non-system namespace with secrets",
			snap: &snapshot.Snapshot{
				Pods: []corev1.Pod{
					podMountingSecret("payments", "api-0"),
					podMountingSecret("frontend", "web-0"),
					podMountingSecret("kube-system", "kube-dns-0"),
				},
				ClusterRoles: []rbacv1.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{Name: "pod-creator"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
					},
				}},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: "global-pod-creator"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "pod-creator"},
					Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "dev@example.com"}},
				}},
			},
			want: Result{Status: "warn", Namespaces: []string{"frontend", "payments"}, AffectedResources: []string{"clusterrolebinding/global-pod-creator"}},
		},
		{
			name: "system subjects are excluded",
			snap: &snapshot.Snapshot{
				Pods: []corev1.Pod{podMountingSecret("payments", "api-0")},
				ClusterRoles: []rbacv1.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{Name: "pod-creator"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
					},
				}},
				ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: "controller-binding"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "pod-creator"},
					Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "system:kube-controller-manager"}},
				}},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "read-only pod access does not warn",
			snap: &snapshot.Snapshot{
				Pods: []corev1.Pod{podMountingSecret("payments", "api-0")},
				Roles: []rbacv1.Role{{
					ObjectMeta: metav1.ObjectMeta{Name: "pod-reader", Namespace: "payments"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
					},
				}},
				RoleBindings: []rbacv1.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: "reader-binding", Namespace: "payments"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-reader"},
					Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "monitor", Namespace: "payments"}},
				}},
			},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "RoleBinding referencing a ClusterRole with wildcard verbs warns in its namespace only",
			snap: &snapshot.Snapshot{
				Pods: []corev1.Pod{
					podMountingSecret("payments", "api-0"),
					podMountingSecret("frontend", "web-0"),
				},
				ClusterRoles: []rbacv1.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{Name: "ns-admin"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
					},
				}},
				RoleBindings: []rbacv1.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: "payments-admin", Namespace: "payments"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "ns-admin"},
					Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}},
				}},
			},
			want: Result{Status: "warn", Namespaces: []string{"payments"}, AffectedResources: []string{"rolebinding/payments/payments-admin"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := podCreateInSecretNamespacesCheck{}.Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
