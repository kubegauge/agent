// netpoleval_test.go table-tests the M5 NetworkPolicy semantics engine against the behaviors
// documented in the official docs (https://kubernetes.io/docs/concepts/services-networking/network-policies/):
// pod isolation defaults, policy additivity, egress-AND-ingress verdicts, the podSelector/
// namespaceSelector OR-vs-AND peer forms, ipBlock with except, numeric/named/endPort ports,
// policyTypes defaulting, and the Verdict.Policy attribution rules. Written BEFORE the engine
// (PLAN-FASE-2.md §8: "suíte de testes de semântica ANTES do engine").
package netpoleval

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// ---- fixtures and builders ---------------------------------------------------------------------

// testNamespaces is the world every case runs in. None of them set kubernetes.io/metadata.name
// explicitly — the metadata.name peer case asserts New injects it.
func testNamespaces() []corev1.Namespace {
	return []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "frontend", Labels: map[string]string{"team": "web"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "backend", Labels: map[string]string{"project": "myproject"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "alice", Labels: map[string]string{"user": "alice"}}},
	}
}

func pod(namespace, name string, labels map[string]string, ports ...corev1.ContainerPort) Peer {
	return Peer{Pod: &PodInfo{Namespace: namespace, Name: name, Labels: labels, Ports: ports}}
}

func external(ip string) Peer { return Peer{IP: ip} }

func tcpFlow(from, to Peer, port int32) Flow {
	return Flow{From: from, To: to, Port: port, Protocol: corev1.ProtocolTCP}
}

func udpFlow(from, to Peer, port int32) Flow {
	return Flow{From: from, To: to, Port: port, Protocol: corev1.ProtocolUDP}
}

func policy(namespace, name string, spec networkingv1.NetworkPolicySpec) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: spec}
}

func sel(labels map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labels}
}

// emptySel is a present-but-empty selector: as a peer podSelector it means "all pods in the
// policy's namespace"; as a peer namespaceSelector it means "all namespaces". Distinct from nil.
func emptySel() *metav1.LabelSelector { return &metav1.LabelSelector{} }

// denyAllIngress / denyAllEgress are the canonical default-deny policies from the docs: empty
// spec.podSelector (selects every pod in the namespace), the policyType, and no rules.
func denyAllIngress(namespace, name string) networkingv1.NetworkPolicy {
	return policy(namespace, name, networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	})
}

func denyAllEgress(namespace, name string) networkingv1.NetworkPolicy {
	return policy(namespace, name, networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
	})
}

// ingressPolicy builds a single-rule ingress policy on pods matching podSel.
func ingressPolicy(namespace, name string, podSel map[string]string, from []networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort) networkingv1.NetworkPolicy {
	return policy(namespace, name, networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: podSel},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: from, Ports: ports}},
	})
}

// egressPolicy builds a single-rule egress policy on pods matching podSel.
func egressPolicy(namespace, name string, podSel map[string]string, to []networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort) networkingv1.NetworkPolicy {
	return policy(namespace, name, networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: podSel},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress:      []networkingv1.NetworkPolicyEgressRule{{To: to, Ports: ports}},
	})
}

func tcpPort(port int32) networkingv1.NetworkPolicyPort {
	p := intstr.FromInt32(port)
	proto := corev1.ProtocolTCP
	return networkingv1.NetworkPolicyPort{Protocol: &proto, Port: &p}
}

func tcpPortRange(port, endPort int32) networkingv1.NetworkPolicyPort {
	pp := tcpPort(port)
	pp.EndPort = &endPort
	return pp
}

// namedPort builds a policy port referencing a container port by name. protocol may be nil
// (defaults to TCP per the API).
func namedPort(name string, protocol *corev1.Protocol) networkingv1.NetworkPolicyPort {
	p := intstr.FromString(name)
	return networkingv1.NetworkPolicyPort{Protocol: protocol, Port: &p}
}

func containerPort(name string, port int32, protocol corev1.Protocol) corev1.ContainerPort {
	return corev1.ContainerPort{Name: name, ContainerPort: port, Protocol: protocol}
}

func ref(namespace, name string) *PolicyRef { return &PolicyRef{Namespace: namespace, Name: name} }

func allowedBy(p *PolicyRef) Verdict { return Verdict{Allowed: true, Policy: p} }
func deniedBy(p *PolicyRef) Verdict  { return Verdict{Allowed: false, Policy: p} }

type evalCase struct {
	name     string
	policies []networkingv1.NetworkPolicy
	flow     Flow
	want     Verdict
}

func runEvalCases(t *testing.T, cases []evalCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.policies, testNamespaces()).Eval(tt.flow)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Eval() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Recurring endpoints: db serves 6379/TCP in default; web lives in frontend.
func dbPod() Peer  { return pod("default", "db", map[string]string{"role": "db"}) }
func webPod() Peer { return pod("frontend", "web", map[string]string{"role": "frontend"}) }

// ---- isolation defaults (docs: "The Two Sorts of Pod Isolation") -------------------------------

func TestEvalIsolationDefaults(t *testing.T) {
	runEvalCases(t, []evalCase{
		{
			name: "no policies: pod-to-pod traffic is default-allow with nil policy",
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: allowedBy(nil),
		},
		{
			name:     "pod selected by an ingress policy with no rules has all ingress denied",
			policies: []networkingv1.NetworkPolicy{denyAllIngress("default", "default-deny-ingress")},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("default", "default-deny-ingress")),
		},
		{
			name: "isolation is per-pod: policy whose podSelector does not match leaves the pod open",
			policies: []networkingv1.NetworkPolicy{policy("default", "isolate-api-only", networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			})},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: allowedBy(nil),
		},
		{
			name:     "policy in another namespace never isolates the destination",
			policies: []networkingv1.NetworkPolicy{denyAllIngress("frontend", "deny-ingress")},
			flow:     tcpFlow(pod("backend", "batch", map[string]string{"role": "batch"}), dbPod(), 6379),
			want:     allowedBy(nil),
		},
		{
			name:     "ingress isolation does not isolate egress: isolated pod can still connect out",
			policies: []networkingv1.NetworkPolicy{denyAllIngress("default", "deny-ingress")},
			flow:     tcpFlow(dbPod(), webPod(), 8080),
			want:     allowedBy(nil),
		},
		{
			name: "allow-all-ingress policy (single empty rule) admits any source",
			policies: []networkingv1.NetworkPolicy{policy("default", "allow-all-ingress", networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
			})},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: allowedBy(ref("default", "allow-all-ingress")),
		},
		{
			name: "external source with no isolation is default-allow",
			flow: tcpFlow(external("203.0.113.7"), dbPod(), 6379),
			want: allowedBy(nil),
		},
		{
			name: "egress to external with no isolation is default-allow",
			flow: tcpFlow(dbPod(), external("203.0.113.7"), 443),
			want: allowedBy(nil),
		},
	})
}

// ---- additivity (docs: "network policies are additive... the order of evaluation does not
// affect the policy result") ----------------------------------------------------------------------

func TestEvalAdditivity(t *testing.T) {
	allowFrontend := ingressPolicy("default", "allow-frontend", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"team": "web"})}}, nil)
	allowBackend := ingressPolicy("default", "allow-backend", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"project": "myproject"})}}, nil)

	runEvalCases(t, []evalCase{
		{
			name:     "deny-all plus allow-from-frontend admits frontend via the allow policy",
			policies: []networkingv1.NetworkPolicy{denyAllIngress("default", "deny-all"), allowFrontend},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(ref("default", "allow-frontend")),
		},
		{
			name:     "a single allow policy also switches the default to deny for everyone else",
			policies: []networkingv1.NetworkPolicy{allowFrontend},
			flow:     tcpFlow(pod("backend", "batch", map[string]string{"role": "batch"}), dbPod(), 6379),
			want:     deniedBy(ref("default", "allow-frontend")),
		},
		{
			name:     "two allow policies form a union: a source matched by either is admitted",
			policies: []networkingv1.NetworkPolicy{allowFrontend, allowBackend},
			flow:     tcpFlow(pod("backend", "batch", map[string]string{"role": "batch"}), dbPod(), 6379),
			want:     allowedBy(ref("default", "allow-backend")),
		},
		{
			name:     "adding a policy never subtracts: frontend stays admitted after allow-backend appears",
			policies: []networkingv1.NetworkPolicy{allowFrontend, allowBackend},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(ref("default", "allow-frontend")),
		},
	})
}

// ---- egress AND ingress: both ends must permit (PLAN §8: "veredito final = egress de A permite
// E ingress de B permite") -------------------------------------------------------------------------

func TestEvalEgressAndIngressBothRequired(t *testing.T) {
	egressOpen := egressPolicy("frontend", "egress-open", nil,
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}}, nil)
	allowFrontend := ingressPolicy("default", "allow-frontend", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"team": "web"})}}, nil)

	runEvalCases(t, []evalCase{
		{
			name:     "destination open but source egress-isolated without rules: denied by the egress side",
			policies: []networkingv1.NetworkPolicy{denyAllEgress("frontend", "deny-egress")},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("frontend", "deny-egress")),
		},
		{
			name:     "source egress allows but destination ingress-isolated without match: denied by the ingress side",
			policies: []networkingv1.NetworkPolicy{egressOpen, denyAllIngress("default", "deny-ingress")},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("default", "deny-ingress")),
		},
		{
			name:     "both sides isolated and both match: allowed, ingress-side policy attributed",
			policies: []networkingv1.NetworkPolicy{egressOpen, allowFrontend},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(ref("default", "allow-frontend")),
		},
		{
			name: "egress port restriction denies even though the destination would allow",
			policies: []networkingv1.NetworkPolicy{egressPolicy("frontend", "egress-80-only", nil,
				[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
				[]networkingv1.NetworkPolicyPort{tcpPort(80)})},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: deniedBy(ref("frontend", "egress-80-only")),
		},
		{
			name: "only the source is isolated and its egress rule matches: allowed, egress-side policy attributed",
			policies: []networkingv1.NetworkPolicy{egressPolicy("frontend", "egress-80-only", nil,
				[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
				[]networkingv1.NetworkPolicyPort{tcpPort(80)})},
			flow: tcpFlow(webPod(), dbPod(), 80),
			want: allowedBy(ref("frontend", "egress-80-only")),
		},
		{
			name: "bare podSelector egress peer targets destinations in the policy's own namespace only",
			policies: []networkingv1.NetworkPolicy{egressPolicy("frontend", "egress-to-cache", nil,
				[]networkingv1.NetworkPolicyPeer{{PodSelector: sel(map[string]string{"role": "cache"})}}, nil)},
			flow: tcpFlow(webPod(), pod("frontend", "cache", map[string]string{"role": "cache"}), 6379),
			want: allowedBy(ref("frontend", "egress-to-cache")),
		},
		{
			name: "bare podSelector egress peer does not match same labels in another namespace",
			policies: []networkingv1.NetworkPolicy{egressPolicy("frontend", "egress-to-cache", nil,
				[]networkingv1.NetworkPolicyPeer{{PodSelector: sel(map[string]string{"role": "cache"})}}, nil)},
			flow: tcpFlow(webPod(), pod("backend", "cache", map[string]string{"role": "cache"}), 6379),
			want: deniedBy(ref("frontend", "egress-to-cache")),
		},
	})
}

// ---- peer selectors: the docs' OR-vs-AND callout ("contains two elements... allows connections
// from Pods in the local Namespace with label role=client, OR from any Pod in any namespace with
// label user=alice" vs the single-element AND form) -------------------------------------------------

func TestEvalPeerSelectors(t *testing.T) {
	fromSameNsFrontendPods := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{PodSelector: sel(map[string]string{"role": "frontend"})}}, nil)
	fromMyprojectNamespaces := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"project": "myproject"})}}, nil)
	andForm := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: sel(map[string]string{"user": "alice"}),
			PodSelector:       sel(map[string]string{"role": "client"}),
		}}, nil)
	orForm := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{
			{NamespaceSelector: sel(map[string]string{"user": "alice"})},
			{PodSelector: sel(map[string]string{"role": "client"})},
		}, nil)

	runEvalCases(t, []evalCase{
		{
			name:     "bare podSelector peer matches pods in the policy's own namespace",
			policies: []networkingv1.NetworkPolicy{fromSameNsFrontendPods},
			flow:     tcpFlow(pod("default", "web", map[string]string{"role": "frontend"}), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "bare podSelector peer does NOT match the same labels in another namespace",
			policies: []networkingv1.NetworkPolicy{fromSameNsFrontendPods},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "namespaceSelector peer admits any pod from a matching namespace regardless of pod labels",
			policies: []networkingv1.NetworkPolicy{fromMyprojectNamespaces},
			flow:     tcpFlow(pod("backend", "anything", map[string]string{"role": "whatever"}), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "namespaceSelector peer denies pods from non-matching namespaces",
			policies: []networkingv1.NetworkPolicy{fromMyprojectNamespaces},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "AND form (one peer, both selectors): role=client in user=alice namespace is admitted",
			policies: []networkingv1.NetworkPolicy{andForm},
			flow:     tcpFlow(pod("alice", "cli", map[string]string{"role": "client"}), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "AND form: right namespace but wrong pod labels is denied",
			policies: []networkingv1.NetworkPolicy{andForm},
			flow:     tcpFlow(pod("alice", "other", map[string]string{"role": "web"}), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "AND form: right pod labels but wrong namespace is denied",
			policies: []networkingv1.NetworkPolicy{andForm},
			flow:     tcpFlow(pod("default", "cli", map[string]string{"role": "client"}), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "OR form (two peers): any pod from the alice namespace is admitted",
			policies: []networkingv1.NetworkPolicy{orForm},
			flow:     tcpFlow(pod("alice", "other", map[string]string{"role": "web"}), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "OR form: role=client in the policy's own namespace is admitted",
			policies: []networkingv1.NetworkPolicy{orForm},
			flow:     tcpFlow(pod("default", "cli", map[string]string{"role": "client"}), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "OR form: role=client in a third namespace matches neither peer (bare podSelector is same-ns only)",
			policies: []networkingv1.NetworkPolicy{orForm},
			flow:     tcpFlow(pod("backend", "cli", map[string]string{"role": "client"}), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name: "empty podSelector peer ({}) selects every pod in the policy's namespace",
			policies: []networkingv1.NetworkPolicy{ingressPolicy("default", "np", map[string]string{"role": "db"},
				[]networkingv1.NetworkPolicyPeer{{PodSelector: emptySel()}}, nil)},
			flow: tcpFlow(pod("default", "anything", nil), dbPod(), 6379),
			want: allowedBy(ref("default", "np")),
		},
		{
			name: "empty podSelector peer still excludes other namespaces",
			policies: []networkingv1.NetworkPolicy{ingressPolicy("default", "np", map[string]string{"role": "db"},
				[]networkingv1.NetworkPolicyPeer{{PodSelector: emptySel()}}, nil)},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: deniedBy(ref("default", "np")),
		},
		{
			name: "empty namespaceSelector peer ({}) selects every pod in every namespace",
			policies: []networkingv1.NetworkPolicy{ingressPolicy("default", "np", map[string]string{"role": "db"},
				[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}}, nil)},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: allowedBy(ref("default", "np")),
		},
		{
			name: "namespaceSelector matches the implicit kubernetes.io/metadata.name label",
			policies: []networkingv1.NetworkPolicy{ingressPolicy("default", "np", map[string]string{"role": "db"},
				[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"kubernetes.io/metadata.name": "frontend"})}}, nil)},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: allowedBy(ref("default", "np")),
		},
		{
			name: "metadata.name peer denies pods from any other namespace",
			policies: []networkingv1.NetworkPolicy{ingressPolicy("default", "np", map[string]string{"role": "db"},
				[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"kubernetes.io/metadata.name": "frontend"})}}, nil)},
			flow: tcpFlow(pod("backend", "batch", map[string]string{"role": "batch"}), dbPod(), 6379),
			want: deniedBy(ref("default", "np")),
		},
	})
}

// ---- ipBlock (docs example: cidr 172.17.0.0/16 except 172.17.1.0/24; egress to 10.0.0.0/24
// port 5978) ---------------------------------------------------------------------------------------

func TestEvalIPBlock(t *testing.T) {
	docIngress := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{
			CIDR:   "172.17.0.0/16",
			Except: []string{"172.17.1.0/24"},
		}}},
		[]networkingv1.NetworkPolicyPort{tcpPort(6379)})
	docEgress := egressPolicy("default", "np-egress", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/24"}}},
		[]networkingv1.NetworkPolicyPort{tcpPort(5978)})

	runEvalCases(t, []evalCase{
		{
			name:     "external IP inside the cidr is admitted",
			policies: []networkingv1.NetworkPolicy{docIngress},
			flow:     tcpFlow(external("172.17.2.5"), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "external IP inside an except range is denied",
			policies: []networkingv1.NetworkPolicy{docIngress},
			flow:     tcpFlow(external("172.17.1.5"), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "external IP outside the cidr is denied",
			policies: []networkingv1.NetworkPolicy{docIngress},
			flow:     tcpFlow(external("192.168.1.5"), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "ipBlock never matches a pod peer whose IP is unknown (conservative degraded mode)",
			policies: []networkingv1.NetworkPolicy{docIngress},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name: "selector peers never match external sources, even namespaceSelector {}",
			policies: []networkingv1.NetworkPolicy{ingressPolicy("default", "np", map[string]string{"role": "db"},
				[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}}, nil)},
			flow: tcpFlow(external("203.0.113.7"), dbPod(), 6379),
			want: deniedBy(ref("default", "np")),
		},
		{
			name:     "egress ipBlock: external destination inside the cidr on the allowed port",
			policies: []networkingv1.NetworkPolicy{docEgress},
			flow:     tcpFlow(dbPod(), external("10.0.0.75"), 5978),
			want:     allowedBy(ref("default", "np-egress")),
		},
		{
			name:     "egress ipBlock: external destination outside the cidr is denied",
			policies: []networkingv1.NetworkPolicy{docEgress},
			flow:     tcpFlow(dbPod(), external("10.0.1.75"), 5978),
			want:     deniedBy(ref("default", "np-egress")),
		},
		{
			name:     "egress ipBlock: wrong port is denied even inside the cidr",
			policies: []networkingv1.NetworkPolicy{docEgress},
			flow:     tcpFlow(dbPod(), external("10.0.0.75"), 443),
			want:     deniedBy(ref("default", "np-egress")),
		},
	})
}

// ---- ipBlock vs pod IPs (validação cruzada com o policy-assistant: o pacote pod→pod carrega o
// pod IP sem SNAT na maioria dos CNIs, então ipBlock DEVE casar pod peer com IP conhecido; sem IP
// o engine permanece conservador e nunca casa) ----------------------------------------------------

func podWithIP(namespace, name, ip string, labels map[string]string) Peer {
	return Peer{Pod: &PodInfo{Namespace: namespace, Name: name, Labels: labels, IP: ip}}
}

func TestEvalIPBlockPodIPs(t *testing.T) {
	docIngress := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{
			CIDR:   "172.17.0.0/16",
			Except: []string{"172.17.1.0/24"},
		}}},
		[]networkingv1.NetworkPolicyPort{tcpPort(6379)})
	allowAllByIP := egressPolicy("frontend", "allow-all-by-ip", nil,
		[]networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}}, nil)

	web := podWithIP("frontend", "web", "172.17.2.5", map[string]string{"role": "frontend"})
	webExcept := podWithIP("frontend", "web", "172.17.1.5", map[string]string{"role": "frontend"})
	db := podWithIP("default", "db", "10.244.0.9", map[string]string{"role": "db"})

	runEvalCases(t, []evalCase{
		{
			name:     "ingress ipBlock matches a source pod whose IP is inside the cidr",
			policies: []networkingv1.NetworkPolicy{docIngress},
			flow:     tcpFlow(web, dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "ingress ipBlock: source pod IP inside an except range is denied",
			policies: []networkingv1.NetworkPolicy{docIngress},
			flow:     tcpFlow(webExcept, dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name: "deny-all + allow-all-by-ipBlock 0.0.0.0/0 reopens pod-to-pod egress",
			policies: []networkingv1.NetworkPolicy{
				denyAllEgress("frontend", "deny-all-egress"),
				allowAllByIP,
			},
			flow: tcpFlow(web, db, 80),
			want: allowedBy(ref("frontend", "allow-all-by-ip")),
		},
	})
}

// ---- ports: numeric, protocol, defaults, empty from, endPort ranges -----------------------------

func TestEvalPorts(t *testing.T) {
	redisFromAnywhere := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		[]networkingv1.NetworkPolicyPort{tcpPort(6379)})
	noPorts := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}}, nil)
	portsNoFrom := ingressPolicy("default", "np", map[string]string{"role": "db"},
		nil, []networkingv1.NetworkPolicyPort{tcpPort(6379)})
	rangePolicy := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		[]networkingv1.NetworkPolicyPort{tcpPortRange(32000, 32768)})

	defaultProtoPort := intstr.FromInt32(6379)
	protoDefaulting := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		[]networkingv1.NetworkPolicyPort{{Port: &defaultProtoPort}}) // Protocol nil → TCP

	runEvalCases(t, []evalCase{
		{
			name:     "rule with TCP/6379 admits that exact port and protocol",
			policies: []networkingv1.NetworkPolicy{redisFromAnywhere},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "different port on the same protocol is denied",
			policies: []networkingv1.NetworkPolicy{redisFromAnywhere},
			flow:     tcpFlow(webPod(), dbPod(), 6380),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "same port on a different protocol is denied",
			policies: []networkingv1.NetworkPolicy{redisFromAnywhere},
			flow:     udpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "rule without ports admits any port",
			policies: []networkingv1.NetworkPolicy{noPorts},
			flow:     tcpFlow(webPod(), dbPod(), 9999),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "rule with ports but empty from admits any pod source on those ports",
			policies: []networkingv1.NetworkPolicy{portsNoFrom},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "rule with ports but empty from admits external sources too",
			policies: []networkingv1.NetworkPolicy{portsNoFrom},
			flow:     tcpFlow(external("203.0.113.7"), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "rule with ports but empty from still denies other ports",
			policies: []networkingv1.NetworkPolicy{portsNoFrom},
			flow:     tcpFlow(webPod(), dbPod(), 80),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "policy port protocol defaults to TCP when unset",
			policies: []networkingv1.NetworkPolicy{protoDefaulting},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "endPort range: below the range is denied",
			policies: []networkingv1.NetworkPolicy{rangePolicy},
			flow:     tcpFlow(webPod(), dbPod(), 31999),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "endPort range: the lower bound is admitted",
			policies: []networkingv1.NetworkPolicy{rangePolicy},
			flow:     tcpFlow(webPod(), dbPod(), 32000),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "endPort range: the upper bound is admitted (inclusive)",
			policies: []networkingv1.NetworkPolicy{rangePolicy},
			flow:     tcpFlow(webPod(), dbPod(), 32768),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "endPort range: above the range is denied",
			policies: []networkingv1.NetworkPolicy{rangePolicy},
			flow:     tcpFlow(webPod(), dbPod(), 32769),
			want:     deniedBy(ref("default", "np")),
		},
	})
}

// ---- named ports: policy port "name" resolves against the DESTINATION pod's container ports ----

func TestEvalNamedPorts(t *testing.T) {
	dbWithRedis := pod("default", "db", map[string]string{"role": "db"},
		containerPort("redis", 6379, corev1.ProtocolTCP))
	dbWithoutNamed := pod("default", "db", map[string]string{"role": "db"},
		containerPort("metrics", 9100, corev1.ProtocolTCP))
	byName := ingressPolicy("default", "np", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		[]networkingv1.NetworkPolicyPort{namedPort("redis", nil)})

	udp := corev1.ProtocolUDP
	dnsPod := pod("default", "coredns", map[string]string{"k8s-app": "kube-dns"},
		containerPort("dns", 53, corev1.ProtocolUDP))
	udpByName := ingressPolicy("default", "np", map[string]string{"k8s-app": "kube-dns"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		[]networkingv1.NetworkPolicyPort{namedPort("dns", &udp)})

	egressByName := egressPolicy("frontend", "np-egress", nil,
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		[]networkingv1.NetworkPolicyPort{namedPort("redis", nil)})

	runEvalCases(t, []evalCase{
		{
			name:     "named policy port resolves to the destination's container port number",
			policies: []networkingv1.NetworkPolicy{byName},
			flow:     tcpFlow(webPod(), dbWithRedis, 6379),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "named port does not admit other numeric ports on the same pod",
			policies: []networkingv1.NetworkPolicy{byName},
			flow:     tcpFlow(webPod(), dbWithRedis, 6380),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "named port that does not resolve on the destination denies the flow",
			policies: []networkingv1.NetworkPolicy{byName},
			flow:     tcpFlow(webPod(), dbWithoutNamed, 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "named port honors its protocol (UDP policy port matches UDP container port)",
			policies: []networkingv1.NetworkPolicy{udpByName},
			flow:     udpFlow(webPod(), dnsPod, 53),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "named ports on egress rules resolve against the destination pod too",
			policies: []networkingv1.NetworkPolicy{egressByName},
			flow:     tcpFlow(webPod(), dbWithRedis, 6379),
			want:     allowedBy(ref("frontend", "np-egress")),
		},
	})
}

// ---- policyTypes defaulting (API spec: Egress is assumed when egress rules exist; Ingress is
// ALWAYS assumed when policyTypes is omitted — the classic egress-only-policy gotcha) -------------

func TestEvalPolicyTypesDefaulting(t *testing.T) {
	ingressOnlyNoTypes := policy("default", "np", networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "db"}},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{PodSelector: sel(map[string]string{"role": "frontend"})}},
		}},
	})
	egressOnlyNoTypes := policy("default", "np", networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "db"}},
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		}},
	})
	egressExplicitType := policy("default", "np", networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "db"}},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: emptySel()}},
		}},
	})

	runEvalCases(t, []evalCase{
		{
			name:     "omitted policyTypes with ingress rules isolates ingress (non-matching source denied)",
			policies: []networkingv1.NetworkPolicy{ingressOnlyNoTypes},
			flow:     tcpFlow(pod("default", "batch", map[string]string{"role": "batch"}), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "omitted policyTypes with only ingress rules does NOT isolate egress",
			policies: []networkingv1.NetworkPolicy{ingressOnlyNoTypes},
			flow:     tcpFlow(dbPod(), webPod(), 8080),
			want:     allowedBy(nil),
		},
		{
			name:     "GOTCHA: omitted policyTypes with only egress rules ALSO isolates ingress (deny-all side effect)",
			policies: []networkingv1.NetworkPolicy{egressOnlyNoTypes},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     deniedBy(ref("default", "np")),
		},
		{
			name:     "the same egress-only policy still allows egress through its rule",
			policies: []networkingv1.NetworkPolicy{egressOnlyNoTypes},
			flow:     tcpFlow(dbPod(), webPod(), 8080),
			want:     allowedBy(ref("default", "np")),
		},
		{
			name:     "explicit policyTypes [Egress] with egress rules leaves ingress open",
			policies: []networkingv1.NetworkPolicy{egressExplicitType},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(nil),
		},
	})
}

// ---- Verdict.Policy attribution determinism (PLAN §8: "a policy que continha a regra de match
// (allowed) ou a policy que ativou o default-deny (denied)") ---------------------------------------

func TestEvalPolicyAttribution(t *testing.T) {
	allowFrontend := ingressPolicy("default", "allow-frontend", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"team": "web"})}}, nil)
	allowWebTeam := ingressPolicy("default", "allow-web-team", map[string]string{"role": "db"},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: sel(map[string]string{"team": "web"})}}, nil)

	runEvalCases(t, []evalCase{
		{
			name: "denied: a pure default-deny is attributed over an allow policy that also isolates",
			policies: []networkingv1.NetworkPolicy{
				allowFrontend,
				denyAllIngress("default", "zz-default-deny"),
			},
			flow: tcpFlow(pod("backend", "batch", map[string]string{"role": "batch"}), dbPod(), 6379),
			want: deniedBy(ref("default", "zz-default-deny")),
		},
		{
			name: "denied: multiple pure deny-alls attribute the first by name, not input order",
			policies: []networkingv1.NetworkPolicy{
				denyAllIngress("default", "deny-b"),
				denyAllIngress("default", "deny-a"),
			},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: deniedBy(ref("default", "deny-a")),
		},
		{
			name: "denied: egress side is evaluated (and attributed) before the ingress side",
			policies: []networkingv1.NetworkPolicy{
				denyAllEgress("frontend", "deny-egress"),
				denyAllIngress("default", "deny-ingress"),
			},
			flow: tcpFlow(webPod(), dbPod(), 6379),
			want: deniedBy(ref("frontend", "deny-egress")),
		},
		{
			name:     "allowed: multiple matching ingress policies attribute the first by name",
			policies: []networkingv1.NetworkPolicy{allowWebTeam, allowFrontend},
			flow:     tcpFlow(webPod(), dbPod(), 6379),
			want:     allowedBy(ref("default", "allow-frontend")),
		},
	})
}
