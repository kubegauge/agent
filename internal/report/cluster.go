// cluster.go implements the distribution heuristic (B5) used when building wire.KubernetesInfo.
package report

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// DetectDistribution applies the B5 heuristic in its exact required order:
// minikube node label -> eks (providerID prefix or version suffix) -> gke -> k3s ->
// kubeadm ConfigMap -> aks -> unknown. Kept as a pure function (no client access) so it stays
// trivially unit-tested (table-driven, see cluster_test.go).
func DetectDistribution(nodes []corev1.Node, serverGitVersion string, kubeadmConfigMapFound bool) string {
	for _, n := range nodes {
		if _, ok := n.Labels["minikube.k8s.io/name"]; ok {
			return "minikube"
		}
	}

	for _, n := range nodes {
		if strings.HasPrefix(n.Spec.ProviderID, "aws://") {
			return "eks"
		}
	}
	if strings.Contains(serverGitVersion, "-eks-") {
		return "eks"
	}

	for _, n := range nodes {
		if strings.HasPrefix(n.Spec.ProviderID, "gce://") {
			return "gke"
		}
	}

	if strings.Contains(serverGitVersion, "+k3s") {
		return "k3s"
	}

	if kubeadmConfigMapFound {
		return "kubeadm"
	}

	for _, n := range nodes {
		if strings.HasPrefix(n.Spec.ProviderID, "azure://") {
			return "aks"
		}
	}

	return "unknown"
}
