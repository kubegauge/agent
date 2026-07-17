// workload_test.go table-tests the worst-of-containers WorkloadPosture aggregation (B5) and the
// buildWorkloads source-selection rule (controllers' pod templates + ownerReferences-less Pods).
package report

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }

func TestAggregatePosture(t *testing.T) {
	tests := []struct {
		name        string
		src         podLike
		saAutomount map[string]*bool
		want        WorkloadPosture
	}{
		{
			name: "everything absent uses spec defaults",
			src: podLike{
				Name: "wl-defaults", Namespace: "ns1", Kind: "Deployment",
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			},
			want: WorkloadPosture{
				Name: "wl-defaults", Namespace: "ns1", Kind: "Deployment", PsaLevel: "baseline",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "none",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "pod-level seccomp + hardened container yields restricted",
			src: podLike{
				Name: "wl-restricted", Namespace: "ns1", Kind: "Deployment",
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   boolPtr(true),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: boolPtr(false),
							ReadOnlyRootFilesystem:   boolPtr(true),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
				},
			},
			want: WorkloadPosture{
				Name: "wl-restricted", Namespace: "ns1", Kind: "Deployment", PsaLevel: "restricted",
				RunAsNonRoot: true, ReadOnlyRootFilesystem: true, AllowPrivilegeEscalation: false,
				CapabilitiesDropAll: true, SeccompProfile: "RuntimeDefault", AppArmorProfile: "none",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "restricted also accepts Localhost seccomp",
			src: podLike{
				Name: "wl-restricted-localhost", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							RunAsNonRoot:             boolPtr(true),
							AllowPrivilegeEscalation: boolPtr(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: strPtr("profiles/my-profile.json")},
						},
					}},
				},
			},
			want: WorkloadPosture{
				Name: "wl-restricted-localhost", Namespace: "ns1", Kind: "Pod", PsaLevel: "restricted",
				RunAsNonRoot: true, AllowPrivilegeEscalation: false, CapabilitiesDropAll: true,
				SeccompProfile: "Localhost", AppArmorProfile: "none", AutomountServiceAccountToken: true,
			},
		},
		{
			name: "container-level overrides pod-level, worst-of wins across containers",
			src: podLike{
				Name: "wl-override", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)},
					Containers: []corev1.Container{
						{Name: "good", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)}},
						{Name: "bad", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(false)}},
					},
				},
			},
			want: WorkloadPosture{
				Name: "wl-override", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				RunAsNonRoot: false, AllowPrivilegeEscalation: true, SeccompProfile: "none",
				AppArmorProfile: "none", AutomountServiceAccountToken: true,
			},
		},
		{
			name: "middle ground: hardened runAsNonRoot alone is baseline, not restricted",
			src: podLike{
				Name: "wl-baseline-mid", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)}}},
				},
			},
			want: WorkloadPosture{
				Name: "wl-baseline-mid", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				RunAsNonRoot: true, AllowPrivilegeEscalation: true, SeccompProfile: "none",
				AppArmorProfile: "none", AutomountServiceAccountToken: true,
			},
		},
		{
			name: "privileged container forces psaLevel privileged",
			src: podLike{
				Name: "wl-priv", Namespace: "ns1", Kind: "DaemonSet",
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)}}}},
			},
			want: WorkloadPosture{
				Name: "wl-priv", Namespace: "ns1", Kind: "DaemonSet", PsaLevel: "privileged",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "none",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "hostNetwork forces privileged even with hardened containers",
			src: podLike{
				Name: "wl-hostnet", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					HostNetwork: true,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   boolPtr(true),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: boolPtr(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
				},
			},
			want: WorkloadPosture{
				Name: "wl-hostnet", Namespace: "ns1", Kind: "Pod", PsaLevel: "privileged",
				RunAsNonRoot: true, AllowPrivilegeEscalation: false, CapabilitiesDropAll: true,
				SeccompProfile: "RuntimeDefault", AppArmorProfile: "none", HostNetwork: true,
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "hostPath volume forces privileged",
			src: podLike{
				Name: "wl-hostpath", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app"}},
					Volumes:    []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}}},
				},
			},
			want: WorkloadPosture{
				Name: "wl-hostpath", Namespace: "ns1", Kind: "Pod", PsaLevel: "privileged",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "none",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "explicit Unconfined seccomp forces privileged",
			src: podLike{
				Name: "wl-unconfined", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}}}},
				},
			},
			want: WorkloadPosture{
				Name: "wl-unconfined", Namespace: "ns1", Kind: "Pod", PsaLevel: "privileged",
				AllowPrivilegeEscalation: true, SeccompProfile: "Unconfined", AppArmorProfile: "none",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "seccomp worst-of: Unconfined on one container beats RuntimeDefault on another",
			src: podLike{
				Name: "wl-seccomp-worst", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "good", SecurityContext: &corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}},
						{Name: "bad", SecurityContext: &corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}}},
					},
				},
			},
			want: WorkloadPosture{
				Name: "wl-seccomp-worst", Namespace: "ns1", Kind: "Pod", PsaLevel: "privileged",
				AllowPrivilegeEscalation: true, SeccompProfile: "Unconfined", AppArmorProfile: "none",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "appArmor structured field (K8s >= 1.30)",
			src: podLike{
				Name: "wl-apparmor-field", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}}}},
				},
			},
			want: WorkloadPosture{
				Name: "wl-apparmor-field", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "runtime/default",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "appArmor legacy annotation: unconfined",
			src: podLike{
				Name: "wl-apparmor-legacy", Namespace: "ns1", Kind: "Pod",
				Annotations: map[string]string{"container.apparmor.security.beta.kubernetes.io/app": "unconfined"},
				Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			},
			want: WorkloadPosture{
				Name: "wl-apparmor-legacy", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "unconfined",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "appArmor legacy annotation: localhost/<profile> prefix",
			src: podLike{
				Name: "wl-apparmor-localhost", Namespace: "ns1", Kind: "Pod",
				Annotations: map[string]string{"container.apparmor.security.beta.kubernetes.io/app": "localhost/my-profile"},
				Spec:        corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			},
			want: WorkloadPosture{
				Name: "wl-apparmor-localhost", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "localhost",
				AutomountServiceAccountToken: true,
			},
		},
		{
			name: "automount: pod-level explicit false wins",
			src: podLike{
				Name: "wl-automount-pod", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{AutomountServiceAccountToken: boolPtr(false), Containers: []corev1.Container{{Name: "app"}}},
			},
			want: WorkloadPosture{
				Name: "wl-automount-pod", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "none",
				AutomountServiceAccountToken: false,
			},
		},
		{
			name: "automount: falls back to the ServiceAccount's field",
			src: podLike{
				Name: "wl-automount-sa", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{ServiceAccountName: "custom-sa", Containers: []corev1.Container{{Name: "app"}}},
			},
			saAutomount: map[string]*bool{"ns1/custom-sa": boolPtr(false)},
			want: WorkloadPosture{
				Name: "wl-automount-sa", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "none",
				AutomountServiceAccountToken: false,
			},
		},
		{
			name: "automount: defaults to true when neither pod nor ServiceAccount set it",
			src: podLike{
				Name: "wl-automount-default", Namespace: "ns1", Kind: "Pod",
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			},
			saAutomount: map[string]*bool{},
			want: WorkloadPosture{
				Name: "wl-automount-default", Namespace: "ns1", Kind: "Pod", PsaLevel: "baseline",
				AllowPrivilegeEscalation: true, SeccompProfile: "none", AppArmorProfile: "none",
				AutomountServiceAccountToken: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saAutomount := tt.saAutomount
			if saAutomount == nil {
				saAutomount = map[string]*bool{}
			}
			got := aggregatePosture(tt.src, saAutomount)
			if got != tt.want {
				t.Errorf("aggregatePosture() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestBuildWorkloadsSourceSelection(t *testing.T) {
	snap := &snapshot.Snapshot{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Name: "dep1", Namespace: "ns1"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
			}},
		}},
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "ns1"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "owned", Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "dep1-abc", UID: "uid-1"}},
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
			},
		},
	}

	got := BuildWorkloads(snap)
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 workloads (dep1 + orphan pod), got %d: %+v", len(got), got)
	}

	kindByName := map[string]string{}
	for _, w := range got {
		kindByName[w.Name] = w.Kind
	}

	if kind, ok := kindByName["dep1"]; !ok || kind != "Deployment" {
		t.Errorf("expected dep1 with kind Deployment, got kind=%q present=%v", kind, ok)
	}
	if kind, ok := kindByName["orphan"]; !ok || kind != "Pod" {
		t.Errorf("expected orphan with kind Pod, got kind=%q present=%v", kind, ok)
	}
	if _, ok := kindByName["owned"]; ok {
		t.Errorf("pod with ownerReferences must be excluded from workloads")
	}
}
