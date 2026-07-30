// network_test.go table-tests BuildNetwork (M5): Service-derived flow candidates, the
// external/internet node, targetPort resolution (numeric, named, defaulted), system-namespace
// scoping, dedup/determinism, and verdict+policy attribution wired through netpoleval.
package report

import (
	"fmt"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kubegauge/agent/internal/snapshot"
)

// ---- fixture builders (nw-prefixed to avoid clashing with other _test.go helpers) --------------

func nwNamespace(name string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func nwDeployment(namespace, name string, labels map[string]string, ports ...corev1.ContainerPort) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img:1.0", Ports: ports}}},
			},
		},
	}
}

func nwContainerPort(name string, port int32, proto corev1.Protocol) corev1.ContainerPort {
	return corev1.ContainerPort{Name: name, ContainerPort: port, Protocol: proto}
}

func nwService(namespace, name string, selector map[string]string, svcType corev1.ServiceType, ports ...corev1.ServicePort) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.ServiceSpec{Selector: selector, Type: svcType, Ports: ports},
	}
}

// nwSvcPort builds a ServicePort; targetPort 0 leaves TargetPort unset (API defaulting to Port is
// the builder's job to honor).
func nwSvcPort(port, targetPort int32, proto corev1.Protocol) corev1.ServicePort {
	sp := corev1.ServicePort{Port: port, Protocol: proto}
	if targetPort != 0 {
		sp.TargetPort = intstr.FromInt32(targetPort)
	}
	return sp
}

func nwNamedSvcPort(port int32, targetPortName string, proto corev1.Protocol) corev1.ServicePort {
	return corev1.ServicePort{Port: port, Protocol: proto, TargetPort: intstr.FromString(targetPortName)}
}

func nwDenyAll(namespace, name string, direction networkingv1.PolicyType) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{direction},
		},
	}
}

// nwAllowAllByIPBlock: egress opened to 0.0.0.0/0 — combined with deny-all, this is the policy pair
// whose semantics the policy-assistant cross-validation pinned down (ipBlock matches pod IP).
func nwAllowAllByIPBlock(namespace, name string) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}},
			}},
		},
	}
}

// nwOwnedPod builds a live pod owned by a controller: a representative IP source, never a node.
func nwOwnedPod(namespace, name string, labels map[string]string, ip string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace, Labels: labels,
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "owner"}},
		},
		Status: corev1.PodStatus{PodIP: ip},
	}
}

func nwBarePod(namespace, name string, labels map[string]string, ip string, ports ...corev1.ContainerPort) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Image: "img:1.0", Ports: ports}}},
		Status:     corev1.PodStatus{PodIP: ip},
	}
}

func nwNode(id, label, namespace, kind string) NetworkNode {
	return NetworkNode{ID: id, Label: label, Namespace: namespace, Kind: kind}
}

func nwInternetNode() NetworkNode {
	return nwNode("external/internet", "Internet", "external", "external")
}

func nwFlow(from, to string, port int, proto, verdict string, policy *string) NetworkFlow {
	return NetworkFlow{From: from, To: to, Port: port, Protocol: proto, Verdict: verdict, Policy: policy}
}

type networkCase struct {
	name      string
	snap      *snapshot.Snapshot
	wantNodes []NetworkNode
	wantFlows []NetworkFlow
}

func runNetworkCases(t *testing.T, cases []networkCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gotNodes, gotFlows := BuildNetwork(tt.snap)
			if !reflect.DeepEqual(gotNodes, tt.wantNodes) {
				t.Errorf("nodes = %+v,\nwant %+v", gotNodes, tt.wantNodes)
			}
			if !reflect.DeepEqual(gotFlows, tt.wantFlows) {
				t.Errorf("flows = %+v,\nwant %+v", gotFlows, tt.wantFlows)
			}
		})
	}
}

// ---- candidate derivation ------------------------------------------------------------------------

func TestBuildNetworkCandidates(t *testing.T) {
	runNetworkCases(t, []networkCase{
		{
			name:      "empty snapshot yields empty non-nil slices",
			snap:      &snapshot.Snapshot{},
			wantNodes: []NetworkNode{},
			wantFlows: []NetworkFlow{},
		},
		{
			name: "service backend receives flows from other workloads; every workload gets an internet egress",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{
					nwDeployment("default", "api", map[string]string{"app": "api"}, nwContainerPort("", 8080, corev1.ProtocolTCP)),
					nwDeployment("default", "client", map[string]string{"app": "client"}),
				},
				Services: []corev1.Service{nwService("default", "api-svc", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwSvcPort(80, 8080, corev1.ProtocolTCP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/api", "api", "default", "pod"),
				nwNode("default/client", "client", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api", 8080, "TCP", "allowed", nil),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "targetPort defaults to the service port when unset",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{
					nwDeployment("default", "redis", map[string]string{"app": "redis"}),
					nwDeployment("default", "client", map[string]string{"app": "client"}),
				},
				Services: []corev1.Service{nwService("default", "redis-svc", map[string]string{"app": "redis"}, corev1.ServiceTypeClusterIP, nwSvcPort(6379, 0, corev1.ProtocolTCP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/client", "client", "default", "pod"),
				nwNode("default/redis", "redis", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/client", "default/redis", 6379, "TCP", "allowed", nil),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/redis", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "named targetPort resolves against the backend's container ports",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{
					nwDeployment("default", "api", map[string]string{"app": "api"}, nwContainerPort("http", 8080, corev1.ProtocolTCP)),
					nwDeployment("default", "client", map[string]string{"app": "client"}),
				},
				Services: []corev1.Service{nwService("default", "api-svc", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwNamedSvcPort(80, "http", corev1.ProtocolTCP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/api", "api", "default", "pod"),
				nwNode("default/client", "client", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api", 8080, "TCP", "allowed", nil),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "backend that cannot resolve a named targetPort gets no service flow",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{
					nwDeployment("default", "api", map[string]string{"app": "api"}, nwContainerPort("metrics", 9100, corev1.ProtocolTCP)),
					nwDeployment("default", "client", map[string]string{"app": "client"}),
				},
				Services: []corev1.Service{nwService("default", "api-svc", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwNamedSvcPort(80, "http", corev1.ProtocolTCP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/api", "api", "default", "pod"),
				nwNode("default/client", "client", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "service without a selector is skipped",
			snap: &snapshot.Snapshot{
				Namespaces:  []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{nwDeployment("default", "app", map[string]string{"app": "web"})},
				Services:    []corev1.Service{nwService("default", "kubernetes", nil, corev1.ServiceTypeClusterIP, nwSvcPort(443, 0, corev1.ProtocolTCP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/app", "app", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/app", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "system-namespace workloads are not sources but their services are destinations",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default"), nwNamespace("kube-system")},
				Deployments: []appsv1.Deployment{
					nwDeployment("kube-system", "coredns", map[string]string{"k8s-app": "kube-dns"}, nwContainerPort("dns", 53, corev1.ProtocolUDP)),
					nwDeployment("default", "app", map[string]string{"app": "web"}),
				},
				Services: []corev1.Service{nwService("kube-system", "kube-dns", map[string]string{"k8s-app": "kube-dns"}, corev1.ServiceTypeClusterIP, nwSvcPort(53, 0, corev1.ProtocolUDP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/app", "app", "default", "pod"),
				nwNode("kube-system/coredns", "coredns", "kube-system", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/app", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/app", "kube-system/coredns", 53, "UDP", "allowed", nil),
			},
		},
		{
			name: "two services on the same backend and port produce one deduped flow",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{
					nwDeployment("default", "api", map[string]string{"app": "api"}),
					nwDeployment("default", "client", map[string]string{"app": "client"}),
				},
				Services: []corev1.Service{
					nwService("default", "api-svc", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwSvcPort(80, 8080, corev1.ProtocolTCP)),
					nwService("default", "api-svc-2", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwSvcPort(8080, 8080, corev1.ProtocolTCP)),
				},
			},
			wantNodes: []NetworkNode{
				nwNode("default/api", "api", "default", "pod"),
				nwNode("default/client", "client", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api", 8080, "TCP", "allowed", nil),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "multiple service ports emit one flow per port",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{
					nwDeployment("default", "api", map[string]string{"app": "api"}),
					nwDeployment("default", "client", map[string]string{"app": "client"}),
				},
				Services: []corev1.Service{nwService("default", "api-svc", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP,
					nwSvcPort(80, 8080, corev1.ProtocolTCP), nwSvcPort(9090, 0, corev1.ProtocolTCP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/api", "api", "default", "pod"),
				nwNode("default/client", "client", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api", 8080, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api", 9090, "TCP", "allowed", nil),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "two backends behind one service each receive flows (including replica-to-replica)",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("default")},
				Deployments: []appsv1.Deployment{
					nwDeployment("default", "api-blue", map[string]string{"app": "api"}),
					nwDeployment("default", "api-green", map[string]string{"app": "api"}),
					nwDeployment("default", "client", map[string]string{"app": "client"}),
				},
				Services: []corev1.Service{nwService("default", "api-svc", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwSvcPort(80, 8080, corev1.ProtocolTCP))},
			},
			wantNodes: []NetworkNode{
				nwNode("default/api-blue", "api-blue", "default", "pod"),
				nwNode("default/api-green", "api-green", "default", "pod"),
				nwNode("default/client", "client", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/api-blue", "default/api-green", 8080, "TCP", "allowed", nil),
				nwFlow("default/api-blue", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/api-green", "default/api-blue", 8080, "TCP", "allowed", nil),
				nwFlow("default/api-green", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api-blue", 8080, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api-green", 8080, "TCP", "allowed", nil),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
	})
}

// ---- internet exposure ---------------------------------------------------------------------------

func TestBuildNetworkInternetIngress(t *testing.T) {
	world := func(svcType corev1.ServiceType) *snapshot.Snapshot {
		return &snapshot.Snapshot{
			Namespaces: []corev1.Namespace{nwNamespace("default")},
			Deployments: []appsv1.Deployment{
				nwDeployment("default", "api", map[string]string{"app": "api"}),
			},
			Services: []corev1.Service{nwService("default", "api-svc", map[string]string{"app": "api"}, svcType, nwSvcPort(80, 8080, corev1.ProtocolTCP))},
		}
	}
	exposedNodes := []NetworkNode{
		nwNode("default/api", "api", "default", "pod"),
		nwInternetNode(),
	}
	exposedFlows := []NetworkFlow{
		nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
		nwFlow("external/internet", "default/api", 8080, "TCP", "allowed", nil),
	}

	runNetworkCases(t, []networkCase{
		{
			name:      "NodePort service gets an ingress flow from the internet node",
			snap:      world(corev1.ServiceTypeNodePort),
			wantNodes: exposedNodes,
			wantFlows: exposedFlows,
		},
		{
			name:      "LoadBalancer service gets an ingress flow from the internet node",
			snap:      world(corev1.ServiceTypeLoadBalancer),
			wantNodes: exposedNodes,
			wantFlows: exposedFlows,
		},
		{
			name: "ClusterIP service gets no ingress flow from the internet node",
			snap: world(corev1.ServiceTypeClusterIP),
			wantNodes: []NetworkNode{
				nwNode("default/api", "api", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
	})
}

// ---- verdict and policy attribution wired through netpoleval ------------------------------------

func TestBuildNetworkVerdicts(t *testing.T) {
	base := func(policies ...networkingv1.NetworkPolicy) *snapshot.Snapshot {
		return &snapshot.Snapshot{
			Namespaces: []corev1.Namespace{nwNamespace("default")},
			Deployments: []appsv1.Deployment{
				nwDeployment("default", "api", map[string]string{"app": "api"}, nwContainerPort("", 8080, corev1.ProtocolTCP)),
				nwDeployment("default", "client", map[string]string{"app": "client"}),
			},
			Services:        []corev1.Service{nwService("default", "api-svc", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwSvcPort(80, 8080, corev1.ProtocolTCP))},
			NetworkPolicies: policies,
		}
	}
	baseNodes := []NetworkNode{
		nwNode("default/api", "api", "default", "pod"),
		nwNode("default/client", "client", "default", "pod"),
		nwInternetNode(),
	}

	allowClient := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-client", Namespace: "default"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}},
			}},
		},
	}
	egressHTTPSOnly := func(name, cidr string) networkingv1.NetworkPolicy {
		proto := corev1.ProtocolTCP
		port := intstr.FromInt32(443)
		return networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To:    []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: cidr}}},
					Ports: []networkingv1.NetworkPolicyPort{{Protocol: &proto, Port: &port}},
				}},
			},
		}
	}

	runNetworkCases(t, []networkCase{
		{
			name:      "default-deny ingress denies the service flow with namespace/name attribution",
			snap:      base(nwDenyAll("default", "deny-all-ingress", networkingv1.PolicyTypeIngress)),
			wantNodes: baseNodes,
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api", 8080, "TCP", "denied", strPtr("default/deny-all-ingress")),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name:      "allow policy admits the service flow and is attributed",
			snap:      base(allowClient),
			wantNodes: baseNodes,
			wantFlows: []NetworkFlow{
				nwFlow("default/api", "external/internet", 443, "TCP", "allowed", nil),
				nwFlow("default/client", "default/api", 8080, "TCP", "allowed", strPtr("default/allow-client")),
				nwFlow("default/client", "external/internet", 443, "TCP", "allowed", nil),
			},
		},
		{
			name: "egress default-deny denies the internet flow with attribution",
			snap: &snapshot.Snapshot{
				Namespaces:      []corev1.Namespace{nwNamespace("default")},
				Deployments:     []appsv1.Deployment{nwDeployment("default", "app", map[string]string{"app": "web"})},
				NetworkPolicies: []networkingv1.NetworkPolicy{nwDenyAll("default", "deny-all-egress", networkingv1.PolicyTypeEgress)},
			},
			wantNodes: []NetworkNode{
				nwNode("default/app", "app", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/app", "external/internet", 443, "TCP", "denied", strPtr("default/deny-all-egress")),
			},
		},
		{
			name: "ipBlock egress to 0.0.0.0/0:443 allows the internet flow (evaluated against the proxy IP)",
			snap: &snapshot.Snapshot{
				Namespaces:      []corev1.Namespace{nwNamespace("default")},
				Deployments:     []appsv1.Deployment{nwDeployment("default", "app", map[string]string{"app": "web"})},
				NetworkPolicies: []networkingv1.NetworkPolicy{egressHTTPSOnly("egress-https", "0.0.0.0/0")},
			},
			wantNodes: []NetworkNode{
				nwNode("default/app", "app", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/app", "external/internet", 443, "TCP", "allowed", strPtr("default/egress-https")),
			},
		},
		{
			name: "ipBlock egress restricted to a private range denies the internet flow",
			snap: &snapshot.Snapshot{
				Namespaces:      []corev1.Namespace{nwNamespace("default")},
				Deployments:     []appsv1.Deployment{nwDeployment("default", "app", map[string]string{"app": "web"})},
				NetworkPolicies: []networkingv1.NetworkPolicy{egressHTTPSOnly("egress-internal", "10.0.0.0/8")},
			},
			wantNodes: []NetworkNode{
				nwNode("default/app", "app", "default", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("default/app", "external/internet", 443, "TCP", "denied", strPtr("default/egress-internal")),
			},
		},
	})
}

// ---- representative IP resolution (M5 cross-validation: ipBlock matches pod IP when the snapshot
// has the live pod; with no live pod the engine degrades to conservative mode) --------------------

func TestBuildNetworkPodIPResolution(t *testing.T) {
	byIP := strPtr("web/allow-all-by-ip")
	policies := []networkingv1.NetworkPolicy{
		nwDenyAll("web", "deny-egress", networkingv1.PolicyTypeEgress),
		nwAllowAllByIPBlock("web", "allow-all-by-ip"),
	}

	runNetworkCases(t, []networkCase{
		{
			name: "deny-all + allow 0.0.0.0/0: pod IP do controller reabre o flow pod-to-pod",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("web")},
				Deployments: []appsv1.Deployment{
					nwDeployment("web", "api", map[string]string{"app": "api"}),
					nwDeployment("web", "client", map[string]string{"app": "client"}),
				},
				Pods: []corev1.Pod{
					nwOwnedPod("web", "api-abc", map[string]string{"app": "api", "pod-template-hash": "abc"}, "10.244.1.7"),
				},
				Services:        []corev1.Service{nwService("web", "api", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwSvcPort(8080, 0, corev1.ProtocolTCP))},
				NetworkPolicies: policies,
			},
			wantNodes: []NetworkNode{
				nwNode("web/api", "api", "web", "pod"),
				nwNode("web/client", "client", "web", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("web/api", "external/internet", 443, "TCP", "allowed", byIP),
				nwFlow("web/client", "external/internet", 443, "TCP", "allowed", byIP),
				nwFlow("web/client", "web/api", 8080, "TCP", "allowed", byIP),
			},
		},
		{
			name: "with no live pod the IP is unknown and the verdict stays conservative (denied)",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("web")},
				Deployments: []appsv1.Deployment{
					nwDeployment("web", "api", map[string]string{"app": "api"}),
					nwDeployment("web", "client", map[string]string{"app": "client"}),
				},
				Services:        []corev1.Service{nwService("web", "api", map[string]string{"app": "api"}, corev1.ServiceTypeClusterIP, nwSvcPort(8080, 0, corev1.ProtocolTCP))},
				NetworkPolicies: policies,
			},
			wantNodes: []NetworkNode{
				nwNode("web/api", "api", "web", "pod"),
				nwNode("web/client", "client", "web", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("web/api", "external/internet", 443, "TCP", "allowed", byIP),
				nwFlow("web/client", "external/internet", 443, "TCP", "allowed", byIP),
				nwFlow("web/client", "web/api", 8080, "TCP", "denied", strPtr("web/deny-egress")),
			},
		},
		{
			name: "bare pod uses its own status.podIP as the ipBlock target",
			snap: &snapshot.Snapshot{
				Namespaces: []corev1.Namespace{nwNamespace("web")},
				Deployments: []appsv1.Deployment{
					nwDeployment("web", "client", map[string]string{"app": "client"}),
				},
				Pods: []corev1.Pod{
					nwBarePod("web", "tool", map[string]string{"run": "tool"}, "10.244.2.9"),
				},
				Services:        []corev1.Service{nwService("web", "tool-svc", map[string]string{"run": "tool"}, corev1.ServiceTypeClusterIP, nwSvcPort(9000, 0, corev1.ProtocolTCP))},
				NetworkPolicies: policies,
			},
			wantNodes: []NetworkNode{
				nwNode("web/client", "client", "web", "pod"),
				nwNode("web/tool", "tool", "web", "pod"),
				nwInternetNode(),
			},
			wantFlows: []NetworkFlow{
				nwFlow("web/client", "external/internet", 443, "TCP", "allowed", byIP),
				nwFlow("web/client", "web/tool", 9000, "TCP", "allowed", byIP),
				nwFlow("web/tool", "external/internet", 443, "TCP", "allowed", byIP),
			},
		},
	})
}

// TestBuildNetworkCapsFlows: on a cluster where the east-west candidate set explodes, the graph
// must stop at MaxFlows instead of growing until the agent OOMs or the API rejects the payload —
// and the flows that survive must still include the exposure story (internet ingress and each
// workload's egress candidate), which is why emission is ordered.
func TestBuildNetworkCapsFlows(t *testing.T) {
	const workloads = 100 // 100 clients x 100 endpoints = 10k east-west candidates

	snap := &snapshot.Snapshot{Namespaces: []corev1.Namespace{nwNamespace("apps")}}
	for i := range workloads {
		name := fmt.Sprintf("svc-%03d", i)
		labels := map[string]string{"app": name}
		snap.Deployments = append(snap.Deployments, nwDeployment("apps", name, labels, nwContainerPort("http", 8080, corev1.ProtocolTCP)))
		svcType := corev1.ServiceTypeClusterIP
		if i == 0 {
			svcType = corev1.ServiceTypeLoadBalancer
		}
		snap.Services = append(snap.Services, nwService("apps", name, labels, svcType, nwSvcPort(80, 8080, corev1.ProtocolTCP)))
	}

	_, flows := BuildNetwork(snap)

	if len(flows) > MaxFlows {
		t.Fatalf("BuildNetwork emitted %d flows, want at most MaxFlows=%d", len(flows), MaxFlows)
	}
	if len(flows) < MaxFlows {
		t.Fatalf("fixture no longer exceeds the cap (%d flows) — it must, or this test proves nothing", len(flows))
	}

	var ingress, egress int
	for _, f := range flows {
		switch {
		case f.From == internetNodeID:
			ingress++
		case f.To == internetNodeID:
			egress++
		}
	}
	if ingress == 0 {
		t.Error("truncation dropped the internet ingress flows, the highest-value part of the graph")
	}
	if egress != workloads {
		t.Errorf("kept %d egress candidates, want one per workload (%d)", egress, workloads)
	}
}
