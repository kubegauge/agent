// psa_test.go table-tests the KG-PS-* checks (psa.go) against hand-built snapshot fixtures.
package checks

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

func TestPsaEnforceLabelCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "namespace without the enforce label fails",
			snap: &snapshot.Snapshot{Namespaces: []corev1.Namespace{testNamespace("default", nil)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"namespace/default"}},
		},
		{
			name: "namespace with the enforce label passes regardless of level",
			snap: &snapshot.Snapshot{Namespaces: []corev1.Namespace{
				testNamespace("frontend", map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kube-system without the label is excluded",
			snap: &snapshot.Snapshot{Namespaces: []corev1.Namespace{testNamespace("kube-system", nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "other PSA labels (audit/warn) don't satisfy the enforce requirement",
			snap: &snapshot.Snapshot{Namespaces: []corev1.Namespace{
				testNamespace("payments", map[string]string{"pod-security.kubernetes.io/audit": "restricted"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{"payments"}, AffectedResources: []string{"namespace/payments"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (psaEnforceLabelCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func podWithSecurityContext(namespace, name string, sc *corev1.SecurityContext) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", SecurityContext: sc}}},
	}
}

func TestPrivilegedPodCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "privileged container outside kube-system fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				podWithSecurityContext("ci-cd", "dind-runner", &corev1.SecurityContext{Privileged: boolPtr(true)}),
			}},
			want: Result{Status: "fail", Namespaces: []string{"ci-cd"}, AffectedResources: []string{"pod/ci-cd/dind-runner"}},
		},
		{
			name: "privileged container in kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				podWithSecurityContext("kube-system", "kube-proxy-abc", &corev1.SecurityContext{Privileged: boolPtr(true)}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "privileged: false passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				podWithSecurityContext("default", "app", &corev1.SecurityContext{Privileged: boolPtr(false)}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "no security context passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithSecurityContext("default", "app", nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "privileged init container also fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "init", SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)}}},
					Containers:     []corev1.Container{{Name: "app"}},
				},
			}}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/app"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (privilegedPodCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func podWithHostFlags(namespace, name string, hostNetwork, hostPID, hostIPC bool) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			HostNetwork: hostNetwork, HostPID: hostPID, HostIPC: hostIPC,
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
}

func TestHostNamespacesCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "hostNetwork outside kube-system fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithHostFlags("default", "hostnet-pod", true, false, false)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/hostnet-pod"}},
		},
		{
			name: "hostPID outside kube-system fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithHostFlags("default", "hostpid-pod", false, true, false)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/hostpid-pod"}},
		},
		{
			name: "hostIPC outside kube-system fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithHostFlags("default", "hostipc-pod", false, false, true)}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/hostipc-pod"}},
		},
		{
			name: "hostNetwork in kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithHostFlags("kube-system", "kube-proxy", true, false, false)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "no host namespaces shared passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithHostFlags("default", "app", false, false, false)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (hostNamespacesCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func podWithHostPath(namespace, name string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			Volumes:    []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}}},
		},
	}
}

func TestHostPathVolumeCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "hostPath outside kube-system warns (not a hard fail)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithHostPath("monitoring", "node-exporter")}},
			want: Result{Status: "warn", Namespaces: []string{"monitoring"}, AffectedResources: []string{"pod/monitoring/node-exporter"}},
		},
		{
			name: "hostPath in kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{podWithHostPath("kube-system", "node-agent")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "no hostPath volumes passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			}}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (hostPathVolumeCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
