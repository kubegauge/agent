// client.go builds the in-cluster Kubernetes clientset for the KubeGauge agent.
package kube

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// InClusterClient builds a *kubernetes.Clientset from the pod's ServiceAccount credentials
// (rest.InClusterConfig). client-go reloads the projected token automatically, so the client
// built once at startup stays valid across token rotations.
func InClusterClient() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("loading in-cluster config (the agent needs to run inside a Kubernetes pod): %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building clientset: %w", err)
	}
	return cs, nil
}
