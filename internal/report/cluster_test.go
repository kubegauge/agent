// cluster_test.go table-tests the DetectDistribution heuristic, including its precedence order.
package report

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDetectDistribution(t *testing.T) {
	minikubeNode := corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"minikube.k8s.io/name": "minikube"}}}
	awsNode := corev1.Node{Spec: corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0123456789"}}
	gceNode := corev1.Node{Spec: corev1.NodeSpec{ProviderID: "gce://my-project/us-central1-a/instance-1"}}
	azureNode := corev1.Node{Spec: corev1.NodeSpec{ProviderID: "azure:///subscriptions/xyz"}}
	plainNode := corev1.Node{}

	tests := []struct {
		name         string
		nodes        []corev1.Node
		gitVersion   string
		kubeadmFound bool
		want         string
	}{
		{name: "minikube label", nodes: []corev1.Node{minikubeNode}, want: "minikube"},
		{name: "aws providerID", nodes: []corev1.Node{awsNode}, want: "eks"},
		{name: "version -eks- suffix without providerID", nodes: []corev1.Node{plainNode}, gitVersion: "v1.29.6-eks-1234567", want: "eks"},
		{name: "gce providerID", nodes: []corev1.Node{gceNode}, want: "gke"},
		{name: "version +k3s suffix", nodes: []corev1.Node{plainNode}, gitVersion: "v1.29.6+k3s1", want: "k3s"},
		{name: "kubeadm configmap found", nodes: []corev1.Node{plainNode}, kubeadmFound: true, want: "kubeadm"},
		{name: "azure providerID", nodes: []corev1.Node{azureNode}, want: "aks"},
		{name: "no signal at all", nodes: []corev1.Node{plainNode}, want: "unknown"},
		{name: "no nodes at all", nodes: nil, want: "unknown"},
		{
			name:  "minikube label takes precedence over aws providerID on same node",
			nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"minikube.k8s.io/name": "minikube"}}, Spec: corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0123456789"}}},
			want:  "minikube",
		},
		{
			name:  "eks is checked before gke when both signals are present",
			nodes: []corev1.Node{awsNode, gceNode},
			want:  "eks",
		},
		{
			name:         "kubeadm configmap is checked before aks providerID",
			nodes:        []corev1.Node{azureNode},
			kubeadmFound: true,
			want:         "kubeadm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDistribution(tt.nodes, tt.gitVersion, tt.kubeadmFound)
			if got != tt.want {
				t.Errorf("DetectDistribution() = %q, want %q", got, tt.want)
			}
		})
	}
}
