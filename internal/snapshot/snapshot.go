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
//
// Scale and failure model. Every list is paginated (listAll: Limit/Continue), so neither the agent
// nor the API server ever materializes a whole 100k-object collection in one response. Resources
// split into two classes: CORE ones (server version, nodes, namespaces, pods, the three workload
// kinds, NetworkPolicies, Services) whose absence would turn the whole report into a lie, and
// OPTIONAL ones whose absence only costs the checks that read them. A core failure aborts the pass;
// an optional failure — a 403 from a trimmed ClusterRole, a timeout, an unreachable extension
// server — is recorded on Snapshot.Uncollected, and internal/checks turns every dependent check
// into "na" rather than a verdict computed from missing data. A partial report with honest gaps
// beats a cluster that never reports at all.
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
)

const (
	// DefaultCollectTimeout bounds one whole collection pass. It replaced a 30s budget that a
	// cluster with tens of thousands of objects could not meet: the pass then failed, every retry
	// failed the same way, and that cluster never produced a single report.
	DefaultCollectTimeout = 10 * time.Minute
	// listPageSize is the Limit on every List call. Pagination keeps each response (and each
	// API server allocation) bounded regardless of cluster size.
	listPageSize = 500
	// maxListPages caps one paginated list at 500k objects — a runaway or looping continue token
	// must not spin forever inside the collection budget.
	maxListPages = 1000
)

// Options tunes one collection pass. The zero value is the production default.
type Options struct {
	// Timeout bounds the whole pass; zero means DefaultCollectTimeout.
	Timeout time.Duration
}

// CollectionError records an OPTIONAL resource kind the collector could not read, and why. It is
// consumed by internal/checks (dependent checks report "na") and logged by the agent; it never
// travels in the push payload.
type CollectionError struct {
	// Resource is the plural resource name as it appears in the ClusterRole ("configmaps").
	Resource string
	Reason   string
}

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

	// Uncollected lists the OPTIONAL resource kinds this pass could not read (see the package doc).
	// Empty on a complete pass. Checks that depend on a listed kind must report "na" instead of a
	// verdict — Missing below is how they ask.
	Uncollected []CollectionError
}

// Missing reports whether an optional resource kind failed to collect in this pass.
func (s *Snapshot) Missing(resource string) bool {
	for _, ce := range s.Uncollected {
		if ce.Resource == resource {
			return true
		}
	}
	return false
}

// pageFunc fetches ONE page of a List call and returns its items plus the continue token for the
// next page ("" on the last page).
type pageFunc[T any] func(ctx context.Context, opts metav1.ListOptions) (items []T, next string, err error)

// listAll pages through a List call (Limit/Continue) instead of asking the API server for every
// object of a kind in a single response.
//
// A continue token stays valid only while the API server keeps the snapshot it names (etcd
// compaction, minutes). A long pass over a big cluster can outlive it, which the API server answers
// with 410 Gone; the whole list is then restarted once, seeing a slightly newer cluster. That is
// harmless for a posture scan and much better than failing the pass.
func listAll[T any](ctx context.Context, page pageFunc[T]) ([]T, error) {
	items, err := listPages(ctx, page)
	if err != nil && (apierrors.IsResourceExpired(err) || apierrors.IsGone(err)) {
		return listPages(ctx, page)
	}
	return items, err
}

func listPages[T any](ctx context.Context, page pageFunc[T]) ([]T, error) {
	var out []T
	opts := metav1.ListOptions{Limit: listPageSize}
	for i := 0; i < maxListPages; i++ {
		items, next, err := page(ctx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		opts.Continue = next
	}
	return nil, fmt.Errorf("list did not finish within %d pages of %d", maxListPages, listPageSize)
}

// collector accumulates one pass, keeping the core/optional distinction in one place.
type collector struct {
	ctx  context.Context
	snap *Snapshot
}

// core runs a paginated list whose failure invalidates the whole report.
func core[T any](c *collector, resource string, page pageFunc[T]) ([]T, error) {
	items, err := listAll(c.ctx, page)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", resource, err)
	}
	return items, nil
}

// optional runs a paginated list whose failure only costs the checks that read it: the reason is
// recorded on the Snapshot and those checks report "na" (see internal/checks).
func optional[T any](c *collector, resource string, page pageFunc[T]) []T {
	items, err := listAll(c.ctx, page)
	if err != nil {
		c.snap.Uncollected = append(c.snap.Uncollected, CollectionError{Resource: resource, Reason: err.Error()})
		return nil
	}
	return items
}

// Take runs one read-only, get/list-only collection pass with the default budget. It never touches
// Secrets, and keeps ConfigMaps as key names only — see this package's doc comment.
func Take(ctx context.Context, cs kubernetes.Interface) (*Snapshot, error) {
	return TakeWithOptions(ctx, cs, Options{})
}

// TakeWithOptions is Take with a caller-chosen budget (the agent exposes it as --collect-timeout,
// for clusters big enough to need more than DefaultCollectTimeout).
func TakeWithOptions(ctx context.Context, cs kubernetes.Interface, opts Options) (*Snapshot, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultCollectTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	snap := &Snapshot{}
	c := &collector{ctx: ctx, snap: snap}
	var err error

	sv, err := cs.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("server version: %w", err)
	}
	snap.ServerVersion = sv

	// ---- core: without these the report would describe a cluster that does not exist -----------

	if snap.Nodes, err = core(c, "nodes", func(ctx context.Context, o metav1.ListOptions) ([]corev1.Node, string, error) {
		l, err := cs.CoreV1().Nodes().List(ctx, o)
		return itemsOf(l, err, func(l *corev1.NodeList) []corev1.Node { return l.Items })
	}); err != nil {
		return nil, err
	}

	if snap.Namespaces, err = core(c, "namespaces", func(ctx context.Context, o metav1.ListOptions) ([]corev1.Namespace, string, error) {
		l, err := cs.CoreV1().Namespaces().List(ctx, o)
		return itemsOf(l, err, func(l *corev1.NamespaceList) []corev1.Namespace { return l.Items })
	}); err != nil {
		return nil, err
	}

	if snap.Pods, err = core(c, "pods", func(ctx context.Context, o metav1.ListOptions) ([]corev1.Pod, string, error) {
		l, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *corev1.PodList) []corev1.Pod { return l.Items })
	}); err != nil {
		return nil, err
	}

	if snap.Deployments, err = core(c, "deployments", func(ctx context.Context, o metav1.ListOptions) ([]appsv1.Deployment, string, error) {
		l, err := cs.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *appsv1.DeploymentList) []appsv1.Deployment { return l.Items })
	}); err != nil {
		return nil, err
	}

	if snap.StatefulSets, err = core(c, "statefulsets", func(ctx context.Context, o metav1.ListOptions) ([]appsv1.StatefulSet, string, error) {
		l, err := cs.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *appsv1.StatefulSetList) []appsv1.StatefulSet { return l.Items })
	}); err != nil {
		return nil, err
	}

	if snap.DaemonSets, err = core(c, "daemonsets", func(ctx context.Context, o metav1.ListOptions) ([]appsv1.DaemonSet, string, error) {
		l, err := cs.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *appsv1.DaemonSetList) []appsv1.DaemonSet { return l.Items })
	}); err != nil {
		return nil, err
	}

	// NetworkPolicies and Services are core despite being small: a missing policy list would make
	// every flow in the network graph look allowed, and a missing Service list would silently empty
	// the graph. Both are wrong answers rather than absent ones.
	if snap.NetworkPolicies, err = core(c, "networkpolicies", func(ctx context.Context, o metav1.ListOptions) ([]networkingv1.NetworkPolicy, string, error) {
		l, err := cs.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *networkingv1.NetworkPolicyList) []networkingv1.NetworkPolicy { return l.Items })
	}); err != nil {
		return nil, err
	}

	if snap.Services, err = core(c, "services", func(ctx context.Context, o metav1.ListOptions) ([]corev1.Service, string, error) {
		l, err := cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *corev1.ServiceList) []corev1.Service { return l.Items })
	}); err != nil {
		return nil, err
	}

	// ---- optional: a failure here degrades the dependent checks to "na", nothing more -----------

	snap.ServiceAccounts = optional(c, "serviceaccounts", func(ctx context.Context, o metav1.ListOptions) ([]corev1.ServiceAccount, string, error) {
		l, err := cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *corev1.ServiceAccountList) []corev1.ServiceAccount { return l.Items })
	})

	snap.Roles = optional(c, "roles", func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.Role, string, error) {
		l, err := cs.RbacV1().Roles(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *rbacv1.RoleList) []rbacv1.Role { return l.Items })
	})

	snap.ClusterRoles = optional(c, "clusterroles", func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.ClusterRole, string, error) {
		l, err := cs.RbacV1().ClusterRoles().List(ctx, o)
		return itemsOf(l, err, func(l *rbacv1.ClusterRoleList) []rbacv1.ClusterRole { return l.Items })
	})

	snap.RoleBindings = optional(c, "rolebindings", func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.RoleBinding, string, error) {
		l, err := cs.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *rbacv1.RoleBindingList) []rbacv1.RoleBinding { return l.Items })
	})

	snap.ClusterRoleBindings = optional(c, "clusterrolebindings", func(ctx context.Context, o metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, error) {
		l, err := cs.RbacV1().ClusterRoleBindings().List(ctx, o)
		return itemsOf(l, err, func(l *rbacv1.ClusterRoleBindingList) []rbacv1.ClusterRoleBinding { return l.Items })
	})

	snap.ValidatingWebhookConfigs = optional(c, "validatingwebhookconfigurations", func(ctx context.Context, o metav1.ListOptions) ([]admissionregistrationv1.ValidatingWebhookConfiguration, string, error) {
		l, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, o)
		return itemsOf(l, err, func(l *admissionregistrationv1.ValidatingWebhookConfigurationList) []admissionregistrationv1.ValidatingWebhookConfiguration {
			return l.Items
		})
	})

	snap.ResourceQuotas = optional(c, "resourcequotas", func(ctx context.Context, o metav1.ListOptions) ([]corev1.ResourceQuota, string, error) {
		l, err := cs.CoreV1().ResourceQuotas(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *corev1.ResourceQuotaList) []corev1.ResourceQuota { return l.Items })
	})

	snap.LimitRanges = optional(c, "limitranges", func(ctx context.Context, o metav1.ListOptions) ([]corev1.LimitRange, string, error) {
		l, err := cs.CoreV1().LimitRanges(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *corev1.LimitRangeList) []corev1.LimitRange { return l.Items })
	})

	snap.Ingresses = optional(c, "ingresses", func(ctx context.Context, o metav1.ListOptions) ([]networkingv1.Ingress, string, error) {
		l, err := cs.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, o)
		return itemsOf(l, err, func(l *networkingv1.IngressList) []networkingv1.Ingress { return l.Items })
	})

	// ConfigMaps (M3: internal/checks/secrets.go). SECURITY-CRITICAL: converted to a metadata-only
	// struct as each page arrives — see ConfigMapMeta's doc comment and this package's. Do not
	// change this to retain the corev1.ConfigMap objects (or their Data/BinaryData) anywhere beyond
	// the conversion. Optional on purpose: an operator who would rather not grant `list configmaps`
	// can remove it (chart value rbac.readConfigMapKeys=false) and lose only KG-SE-003.
	snap.ConfigMaps = make([]ConfigMapMeta, 0)
	snap.ConfigMaps = append(snap.ConfigMaps, optional(c, "configmaps", func(ctx context.Context, o metav1.ListOptions) ([]ConfigMapMeta, string, error) {
		l, err := cs.CoreV1().ConfigMaps(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		metas := make([]ConfigMapMeta, 0, len(l.Items))
		for _, cm := range l.Items {
			keys := make([]string, 0, len(cm.Data)+len(cm.BinaryData))
			for k := range cm.Data {
				keys = append(keys, k)
			}
			for k := range cm.BinaryData {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			metas = append(metas, ConfigMapMeta{Name: cm.Name, Namespace: cm.Namespace, Keys: keys})
		}
		return metas, l.Continue, nil
	})...)

	_, cmErr := cs.CoreV1().ConfigMaps(kubeadmConfigMapNamespace).Get(ctx, kubeadmConfigMapName, metav1.GetOptions{})
	snap.KubeadmConfigMapFound = cmErr == nil

	return snap, nil
}

// listMeta is what every generated *List type provides through its embedded metav1.ListMeta: the
// continue token that drives pagination.
type listMeta interface {
	GetContinue() string
}

// itemsOf adapts a typed client's (list, error) result to pageFunc's (items, continue, error).
func itemsOf[L listMeta, T any](list L, err error, items func(L) []T) ([]T, string, error) {
	if err != nil {
		return nil, "", err
	}
	return items(list), list.GetContinue(), nil
}
