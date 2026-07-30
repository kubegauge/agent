// Package snapshot performs a single read-only collection pass (get/list only) and returns a typed
// Snapshot for internal/report to assemble into a ScanReport.
//
// Secrets are NEVER listed. Discarding the values in-process was not enough: the ServiceAccount
// token would still be a cluster-wide credential oracle for anyone who reached the pod, which is
// exactly the pattern the agent's own KG-RB-006 fails a Role for. Kubernetes RBAC cannot express
// "list metadata only", so the grant itself is gone from the chart's ClusterRole and this package
// has no code path that can read a Secret even by accident (TestSnapshotNeverListsSecrets).
//
// ConfigMaps ARE listed, but only ever as ConfigMapMeta (name/namespace/key NAMES, never values):
// KG-SE-003 matches key names against a credential-looking pattern, which no metadata-only
// projection served by the API server can provide. Take converts each corev1.ConfigMap in the same
// loop that lists it, so values never survive past that conversion — never stored on Snapshot,
// never serialized into a ScanReport, never logged (TestConfigMapValuesNeverLeaveSnapshot).
package snapshot

import (
	"context"
	"fmt"
	"sort"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
)

// collectTimeout bounds the whole collection pass (B4: one context.WithTimeout of 30s covering everything).
const collectTimeout = 30 * time.Second

// kubeadmConfigMapNamespace/Name identify the ConfigMap used as a kubeadm-distribution signal (best effort; see Take).
const (
	kubeadmConfigMapNamespace = "kube-system"
	kubeadmConfigMapName      = "kubeadm-config"
)

// ConfigMapMeta is the ONLY shape a ConfigMap is ever allowed to take once it enters this
// package's output: KG-SE-003's credential-heuristic check (checks/secrets.go) matches KEY NAMES
// against a regex (password|token|secret|...) — it must never see, and therefore can never leak,
// the corresponding values. Only Data/BinaryData's keys are kept, never their values.
type ConfigMapMeta struct {
	Name      string
	Namespace string
	Keys      []string
}

// Snapshot holds the raw, typed results of a single read-only collection pass against a cluster.
type Snapshot struct {
	ServerVersion   *version.Info
	Nodes           []corev1.Node
	Namespaces      []corev1.Namespace
	Pods            []corev1.Pod
	Deployments     []appsv1.Deployment
	StatefulSets    []appsv1.StatefulSet
	DaemonSets      []appsv1.DaemonSet
	NetworkPolicies []networkingv1.NetworkPolicy
	ServiceAccounts []corev1.ServiceAccount

	// Services (M5: report.BuildNetwork). Flow candidates for the network graph derive from
	// Services — "who exposes which port to whom" (PLAN-FASE-2.md §8) — instead of O(n²)
	// arbitrary workload pairs.
	Services []corev1.Service

	// RBAC resources (M2: internal/checks/rbac.go). get/list only, same error handling as every
	// other resource below — a failure here fails the whole snapshot rather than degrading, since
	// KG-RB-* checks have no meaningful partial result without them.
	Roles               []rbacv1.Role
	ClusterRoles        []rbacv1.ClusterRole
	RoleBindings        []rbacv1.RoleBinding
	ClusterRoleBindings []rbacv1.ClusterRoleBinding

	// ConfigMaps (M3: internal/checks/secrets.go, KG-SE-003). SECURITY-CRITICAL: a metadata-only
	// projection (ConfigMapMeta above) — see Take's doc comment. Never add a field here that could
	// carry a ConfigMap's values. There is deliberately no Secrets field: see the package doc.
	ConfigMaps []ConfigMapMeta

	// ValidatingWebhookConfigs (KG-SU-004: internal/checks/supplychain.go). Cluster-scoped
	// admission webhook configurations, listed so the image-signature-verification check can
	// recognize enforcement stacks (sigstore policy-controller, Connaisseur, Kyverno) by webhook
	// name alone — no dynamic client / CRD access needed. Full objects: they carry no sensitive
	// payload (service refs, rules and a CA bundle, which is public key material).
	ValidatingWebhookConfigs []admissionregistrationv1.ValidatingWebhookConfiguration

	// ResourceQuotas and LimitRanges (KG-QT-*: internal/checks/resourcegov.go). Namespaced
	// resource-governance objects, listed so the resource-governance checks can tell which workload
	// namespaces have a quota/limit boundary configured. Full objects: they carry no sensitive
	// payload, only resource ceilings (ResourceQuota.Spec.Hard) and per-container defaults/bounds
	// (LimitRange.Spec.Limits) — the checks only need the namespace they belong to.
	ResourceQuotas []corev1.ResourceQuota
	LimitRanges    []corev1.LimitRange

	// Ingresses (KG-IN-*: internal/checks/ingress.go). Namespaced HTTP(S) exposure objects, listed
	// so the ingress-exposure check can tell which exposed hosts terminate TLS. Full objects: they
	// carry no sensitive payload, only host/path routing and references (by name) to the TLS
	// Secrets — never the Secret material itself.
	Ingresses []networkingv1.Ingress

	// KubeadmConfigMapFound records whether kube-system/kubeadm-config exists.
	// It is a best-effort signal consumed only by the report package's distribution
	// heuristic (kubeadm clusters keep their bootstrap config here). Any error from
	// this particular Get (403, 404, or otherwise) is treated as "not found" rather
	// than failing the whole snapshot, since it is not part of the core B4 resource
	// list and the heuristic must degrade gracefully. This is a deliberate, narrow
	// deviation from "collect only what is listed": the field is required for the B5
	// distribution heuristic and report.DetectDistribution/wire.Build only ever see the
	// Snapshot, never a live client, so the lookup has to happen here.
	KubeadmConfigMapFound bool

	// ImageVulns is filled by internal/trivy AFTER Take (enrichment, not part of the API
	// get/list pass). nil = scanner unavailable/disabled — see imagevulns.go.
	ImageVulns *ImageVulns
}

// Take runs one read-only, get/list-only collection pass and returns a Snapshot. It never touches
// Secrets, and keeps ConfigMaps as key names only — see this package's doc comment.
func Take(ctx context.Context, cs kubernetes.Interface) (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()

	snap := &Snapshot{}

	sv, err := cs.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("server version: %w", err)
	}
	snap.ServerVersion = sv

	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	snap.Nodes = nodeList.Items

	nsList, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	snap.Namespaces = nsList.Items

	podList, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	snap.Pods = podList.Items

	depList, err := cs.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	snap.Deployments = depList.Items

	stsList, err := cs.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	snap.StatefulSets = stsList.Items

	dsList, err := cs.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	snap.DaemonSets = dsList.Items

	npList, err := cs.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networkpolicies: %w", err)
	}
	snap.NetworkPolicies = npList.Items

	saList, err := cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	snap.ServiceAccounts = saList.Items

	svcList, err := cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	snap.Services = svcList.Items

	roleList, err := cs.RbacV1().Roles(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	snap.Roles = roleList.Items

	clusterRoleList, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	snap.ClusterRoles = clusterRoleList.Items

	roleBindingList, err := cs.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	snap.RoleBindings = roleBindingList.Items

	clusterRoleBindingList, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	snap.ClusterRoleBindings = clusterRoleBindingList.Items

	vwcList, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list validatingwebhookconfigurations: %w", err)
	}
	snap.ValidatingWebhookConfigs = vwcList.Items

	rqList, err := cs.CoreV1().ResourceQuotas(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list resourcequotas: %w", err)
	}
	snap.ResourceQuotas = rqList.Items

	lrList, err := cs.CoreV1().LimitRanges(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list limitranges: %w", err)
	}
	snap.LimitRanges = lrList.Items

	ingList, err := cs.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingresses: %w", err)
	}
	snap.Ingresses = ingList.Items

	// ConfigMaps (M3: internal/checks/secrets.go). SECURITY-CRITICAL: converted to a metadata-only
	// struct in this same loop — see ConfigMapMeta's doc comment and this package's. Do not change
	// this loop to retain the corev1.ConfigMap objects (or their Data/BinaryData) anywhere beyond
	// the conversion.
	cmList, err := cs.CoreV1().ConfigMaps(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list configmaps: %w", err)
	}
	snap.ConfigMaps = make([]ConfigMapMeta, 0, len(cmList.Items))
	for _, cm := range cmList.Items {
		keys := make([]string, 0, len(cm.Data)+len(cm.BinaryData))
		for k := range cm.Data {
			keys = append(keys, k)
		}
		for k := range cm.BinaryData {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		snap.ConfigMaps = append(snap.ConfigMaps, ConfigMapMeta{Name: cm.Name, Namespace: cm.Namespace, Keys: keys})
	}

	_, cmErr := cs.CoreV1().ConfigMaps(kubeadmConfigMapNamespace).Get(ctx, kubeadmConfigMapName, metav1.GetOptions{})
	snap.KubeadmConfigMapFound = cmErr == nil

	return snap, nil
}
