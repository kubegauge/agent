// threatdetection_test.go covers KG-TD-001 (threat-detection, threatdetection.go): pass when a
// recognized runtime threat-detection agent runs as a DaemonSet, warn when none is found. The
// verdict is a pure function of each DaemonSet's name and container images, so the table builds
// DaemonSet fixtures directly as struct literals.
package checks

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// rtDaemonSet builds a DaemonSet fixture with the given namespace/name and one container per image
// (only Name/Namespace and container Images matter to KG-TD-001).
func rtDaemonSet(namespace, name string, images ...string) appsv1.DaemonSet {
	containers := make([]corev1.Container, len(images))
	for i, img := range images {
		containers[i] = corev1.Container{Image: img}
	}
	return appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: containers}},
		},
	}
}

func TestRuntimeThreatDetectionCheck(t *testing.T) {
	cases := []struct {
		name          string
		daemonSets    []appsv1.DaemonSet
		wantStatus    string
		wantNS        []string
		wantResources []string
	}{
		{
			name: "Falco reconhecido pelo nome do DaemonSet",
			daemonSets: []appsv1.DaemonSet{
				rtDaemonSet("falco", "falco", "docker.io/falcosecurity/falco:0.38.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"falco"},
			wantResources: []string{"daemonset/falco/falco"},
		},
		{
			name: "Tetragon recognized by image, generic name",
			daemonSets: []appsv1.DaemonSet{
				rtDaemonSet("kube-system", "runtime-agent", "quay.io/cilium/tetragon:v1.1.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"kube-system"},
			wantResources: []string{"daemonset/kube-system/runtime-agent"},
		},
		{
			name: "case-insensitive no nome",
			daemonSets: []appsv1.DaemonSet{
				rtDaemonSet("security", "KubeArmor", "kubearmor/kubearmor:stable"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"security"},
			wantResources: []string{"daemonset/security/KubeArmor"},
		},
		{
			name: "DaemonSets with no detection tool (logging only) → warn",
			daemonSets: []appsv1.DaemonSet{
				rtDaemonSet("logging", "fluentd", "fluent/fluentd:v1.16"),
				rtDaemonSet("kube-system", "kube-proxy", "registry.k8s.io/kube-proxy:v1.30.0"),
			},
			wantStatus:    "warn",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name:          "cluster sem DaemonSets → warn",
			daemonSets:    nil,
			wantStatus:    "warn",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name: "several detectors across distinct namespaces (sorted)",
			daemonSets: []appsv1.DaemonSet{
				rtDaemonSet("falco", "falco", "falcosecurity/falco:0.38.0"),
				rtDaemonSet("logging", "fluentd", "fluent/fluentd:v1.16"),
				rtDaemonSet("kube-system", "sysdig-agent", "quay.io/sysdig/agent:13.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"falco", "kube-system"},
			wantResources: []string{"daemonset/falco/falco", "daemonset/kube-system/sysdig-agent"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runtimeThreatDetectionCheck{}.Run(&snapshot.Snapshot{DaemonSets: tc.daemonSets})
			if res.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", res.Status, tc.wantStatus)
			}
			if !reflect.DeepEqual(res.Namespaces, tc.wantNS) {
				t.Errorf("Namespaces = %v, want %v", res.Namespaces, tc.wantNS)
			}
			if !reflect.DeepEqual(res.AffectedResources, tc.wantResources) {
				t.Errorf("AffectedResources = %v, want %v", res.AffectedResources, tc.wantResources)
			}
		})
	}
}

func TestRuntimeThreatDetectionCheckID(t *testing.T) {
	if got := (runtimeThreatDetectionCheck{}).ID(); got != "KG-TD-001" {
		t.Errorf("ID() = %q, want KG-TD-001", got)
	}
}
