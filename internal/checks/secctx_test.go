// secctx_test.go table-tests the KG-SC-* checks (secctx.go) against hand-built snapshot fixtures.
package checks

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// scPod builds an ownerReferences-less Pod (kind "Pod" for WorkloadSources/BuildWorkloads
// purposes) with a single container "app" carrying the given container-level SecurityContext,
// optionally under a pod-level PodSecurityContext.
func scPod(namespace, name string, podSC *corev1.PodSecurityContext, containerSC *corev1.SecurityContext) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			SecurityContext: podSC,
			Containers:      []corev1.Container{{Name: "app", SecurityContext: containerSC}},
		},
	}
}

func TestRunAsNonRootCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "container without runAsNonRoot fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, nil)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "container-level runAsNonRoot: true passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("kube-system", "coredns", nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "pod-level runAsNonRoot: true is inherited when the container leaves it unset",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)}, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "container-level false overrides pod-level true (container precedence)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api",
				&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)},
				&corev1.SecurityContext{RunAsNonRoot: boolPtr(false)},
			)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "container-level true overrides pod-level false (container precedence)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api",
				&corev1.PodSecurityContext{RunAsNonRoot: boolPtr(false)},
				&corev1.SecurityContext{RunAsNonRoot: boolPtr(true)},
			)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (runAsNonRootCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReadOnlyRootFilesystemCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "container without readOnlyRootFilesystem fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, nil)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "readOnlyRootFilesystem: true passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, &corev1.SecurityContext{ReadOnlyRootFilesystem: boolPtr(true)})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("kube-system", "coredns", nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "readOnlyRootFilesystem: false explicitly still fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, &corev1.SecurityContext{ReadOnlyRootFilesystem: boolPtr(false)})}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (readOnlyRootFilesystemCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCapabilitiesDropAllCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "no capabilities set warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, nil)}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "capabilities.drop ALL passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "dropping specific capabilities without ALL still warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"NET_ADMIN"}},
			})}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("kube-system", "coredns", nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (capabilitiesDropAllCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAllowPrivilegeEscalationCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "absent allowPrivilegeEscalation defaults to true and fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, nil)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "explicit allowPrivilegeEscalation: true fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(true)})}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "explicit allowPrivilegeEscalation: false passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("default", "api", nil, &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false)})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kube-system is excluded even with escalation allowed",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{scPod("kube-system", "coredns", nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (allowPrivilegeEscalationCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResourceLimitsCheck(t *testing.T) {
	limits := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse("250m"),
		corev1.ResourceMemory: resource.MustParse("128Mi"),
	}

	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "container without resources.limits fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			}}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "container with resources.limits set passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "app", Resources: corev1.ResourceRequirements{Limits: limits},
				}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "init container missing limits fails even when the main container is compliant",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "init"}},
					Containers:     []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{Limits: limits}}},
				},
			}}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: "kube-system"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (resourceLimitsCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
