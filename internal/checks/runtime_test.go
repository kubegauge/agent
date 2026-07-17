// runtime_test.go table-tests the KG-RT-* checks (runtime.go) against hand-built snapshot fixtures.
package checks

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

func strPtr(s string) *string { return &s }

// rtPod builds an ownerReferences-less Pod with a single container "app", allowing pod- and
// container-level SecurityContext plus pod-level annotations, to exercise seccomp/AppArmor
// precedence and the legacy AppArmor annotation in the KG-RT-* checks.
func rtPod(namespace, name string, annotations map[string]string, podSC *corev1.PodSecurityContext, containerSC *corev1.SecurityContext) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: annotations},
		Spec: corev1.PodSpec{
			SecurityContext: podSC,
			Containers:      []corev1.Container{{Name: "app", SecurityContext: containerSC}},
		},
	}
}

func TestSeccompRuntimeDefaultCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no seccomp profile fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, nil)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "container-level RuntimeDefault passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "pod-level RuntimeDefault is inherited by a container that sets nothing",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			}, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "custom Localhost profile still fails (mock's audit command matches the literal string only)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: strPtr("profiles/my-profile.json")},
			})}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "container-level Unconfined overrides a good pod-level RuntimeDefault (container precedence)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil,
				&corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
				&corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}},
			)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("kube-system", "coredns", nil, nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (seccompRuntimeDefaultCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAppArmorRuntimeDefaultCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no AppArmor profile warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, nil)}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "structured appArmorProfile runtime/default (K8s >= 1.30) passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault},
			})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "legacy annotation runtime/default passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api",
				map[string]string{"container.apparmor.security.beta.kubernetes.io/app": "runtime/default"},
				nil, nil,
			)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "legacy annotation unconfined warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api",
				map[string]string{"container.apparmor.security.beta.kubernetes.io/app": "unconfined"},
				nil, nil,
			)}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("kube-system", "coredns", nil, nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (appArmorRuntimeDefaultCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNoUnconfinedProfileCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "explicit seccomp Unconfined fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
			})}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "explicit AppArmor unconfined (structured field) fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined},
			})}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "explicit AppArmor unconfined via legacy annotation fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api",
				map[string]string{"container.apparmor.security.beta.kubernetes.io/app": "unconfined"},
				nil, nil,
			)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "absent profile (none) passes - only an explicit Unconfined is worse than absent",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "RuntimeDefault seccomp + runtime/default AppArmor passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				SeccompProfile:  &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault},
			})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kube-system is excluded even with Unconfined",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("kube-system", "coredns", nil, nil, &corev1.SecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
			})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (noUnconfinedProfileCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSELinuxOptionsCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "nothing set yields info, not pass",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, nil)}},
			want: Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "pod-level seLinuxOptions.user customization warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, &corev1.PodSecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{User: "user_u"},
			}, nil)}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "container-level seLinuxOptions.role customization warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{Role: "object_r"},
			})}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "init-container-level customization also warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "init", SecurityContext: &corev1.SecurityContext{
						SELinuxOptions: &corev1.SELinuxOptions{User: "user_u"},
					}}},
					Containers: []corev1.Container{{Name: "app"}},
				},
			}}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "only type/level set (no user/role) does not count as a customization",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("default", "api", nil, nil, &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{Type: "container_t", Level: "s0:c123,c456"},
			})}},
			want: Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kube-system is excluded even with a customization",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{rtPod("kube-system", "coredns", nil, nil, &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{User: "user_u"},
			})}},
			want: Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (seLinuxOptionsCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
