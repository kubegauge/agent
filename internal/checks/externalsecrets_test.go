// externalsecrets_test.go covers KG-SE-004 (secrets, externalsecrets.go): pass when a recognized
// external secrets-management controller runs as a Deployment, info when none is found. The verdict
// is a pure function of each Deployment's name and container images, so the table builds Deployment
// fixtures directly as struct literals.
package checks

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// esmDeployment builds a Deployment fixture with the given namespace/name and one container per
// image (only Name/Namespace and container Images matter to KG-SE-004).
func esmDeployment(namespace, name string, images ...string) appsv1.Deployment {
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

func TestExternalSecretsManagementCheck(t *testing.T) {
	cases := []struct {
		name          string
		deployments   []appsv1.Deployment
		wantStatus    string
		wantNS        []string
		wantResources []string
	}{
		{
			name: "External Secrets Operator recognized by name",
			deployments: []appsv1.Deployment{
				esmDeployment("external-secrets", "external-secrets", "ghcr.io/external-secrets/external-secrets:v0.9.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"external-secrets"},
			wantResources: []string{"deploy/external-secrets/external-secrets"},
		},
		{
			name: "Vault Agent Injector recognized by image (vault-k8s), generic name",
			deployments: []appsv1.Deployment{
				esmDeployment("vault", "injector", "hashicorp/vault-k8s:1.4.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"vault"},
			wantResources: []string{"deploy/vault/injector"},
		},
		{
			name: "Sealed Secrets controller, matched case-insensitively",
			deployments: []appsv1.Deployment{
				esmDeployment("kube-system", "Sealed-Secrets-Controller", "docker.io/bitnami/sealed-secrets-controller:0.27.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"kube-system"},
			wantResources: []string{"deploy/kube-system/Sealed-Secrets-Controller"},
		},
		{
			name: "ordinary Deployments (no external management) → info",
			deployments: []appsv1.Deployment{
				esmDeployment("default", "web", "nginx:1.27"),
				esmDeployment("payments", "gateway", "myco/gateway:2.1"),
			},
			wantStatus:    "info",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name:          "cluster with no Deployments -> info",
			deployments:   nil,
			wantStatus:    "info",
			wantNS:        []string{},
			wantResources: []string{},
		},
		{
			name: "multiple controllers across distinct namespaces (sorted)",
			deployments: []appsv1.Deployment{
				esmDeployment("vault", "vault-agent-injector", "hashicorp/vault-k8s:1.4.0"),
				esmDeployment("default", "web", "nginx:1.27"),
				esmDeployment("external-secrets", "external-secrets", "ghcr.io/external-secrets/external-secrets:v0.9.0"),
			},
			wantStatus:    "pass",
			wantNS:        []string{"external-secrets", "vault"},
			wantResources: []string{"deploy/external-secrets/external-secrets", "deploy/vault/vault-agent-injector"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := externalSecretsManagementCheck{}.Run(&snapshot.Snapshot{Deployments: tc.deployments})
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

func TestExternalSecretsManagementCheckID(t *testing.T) {
	if got := (externalSecretsManagementCheck{}).ID(); got != "KG-SE-004" {
		t.Errorf("ID() = %q, want KG-SE-004", got)
	}
}
