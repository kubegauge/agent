// backupdr_test.go covers KG-DR-001 (backup-dr, backupdr.go): pass when a recognized backup/DR
// solution runs as a Deployment, warn when none is found. The verdict is a pure function of each
// Deployment's name and container images, so the table builds Deployment fixtures directly as
// struct literals.
package checks

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// drDeployment builds a Deployment fixture with the given namespace/name and one container per
// image (only Name/Namespace and container Images matter to KG-DR-001).
func drDeployment(namespace, name string, images ...string) appsv1.Deployment {
	containers := make([]corev1.Container, len(images))
	for i, img := range images {
		containers[i] = corev1.Container{Image: img}
	}
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: containers}},
		},
	}
}

func TestBackupDisasterRecoveryCheck(t *testing.T) {
	cases := []struct {
		name          string
		deployments   []appsv1.Deployment
		wantStatus    string
		wantNS        []string
		wantResources []string
	}{
		{
			name: "Velero reconhecido pelo nome do Deployment",
			deployments: []appsv1.Deployment{
				drDeployment("velero", "velero", "velero/velero:v1.14.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"velero"},
			wantResources: []string{"deploy/velero/velero"},
		},
		{
			name: "Velero recognized by image, generic name",
			deployments: []appsv1.Deployment{
				drDeployment("backup", "backup-controller", "docker.io/velero/velero:v1.13.2"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"backup"},
			wantResources: []string{"deploy/backup/backup-controller"},
		},
		{
			name: "Kasten K10 case-insensitive no nome",
			deployments: []appsv1.Deployment{
				drDeployment("kasten-io", "K10-catalog", "gcr.io/kasten-images/catalog:6.5.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"kasten-io"},
			wantResources: []string{"deploy/kasten-io/K10-catalog"},
		},
		{
			name: "Deployments with no backup solution (app only) → warn",
			deployments: []appsv1.Deployment{
				drDeployment("default", "frontend", "nginx:1.27"),
				drDeployment("kube-system", "coredns", "registry.k8s.io/coredns/coredns:v1.11.1"),
			},
			wantStatus:    "warn",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name:          "cluster sem Deployments → warn",
			deployments:   nil,
			wantStatus:    "warn",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name: "several solutions across distinct namespaces (sorted)",
			deployments: []appsv1.Deployment{
				drDeployment("velero", "velero", "velero/velero:v1.14.0"),
				drDeployment("default", "frontend", "nginx:1.27"),
				drDeployment("trilio", "trilio-operator", "docker.io/trilio/k8s-triliovault-operator:3.0.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"trilio", "velero"},
			wantResources: []string{"deploy/trilio/trilio-operator", "deploy/velero/velero"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := backupDisasterRecoveryCheck{}.Run(&snapshot.Snapshot{Deployments: tc.deployments})
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

func TestBackupDisasterRecoveryCheckID(t *testing.T) {
	if got := (backupDisasterRecoveryCheck{}).ID(); got != "KG-DR-001" {
		t.Errorf("ID() = %q, want KG-DR-001", got)
	}
}
