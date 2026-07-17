// Package netpoleval implements the M5 NetworkPolicy semantics engine (PLAN-FASE-2.md §8): given
// the cluster's NetworkPolicies and Namespaces, it answers "is flow A→B on port/protocol allowed
// or denied, and which policy is responsible?" following upstream semantics
// (https://kubernetes.io/docs/concepts/services-networking/network-policies/):
//
//   - Policies are ADDITIVE: there are no deny rules; a rule in any policy can only allow more.
//   - A pod becomes ISOLATED in a direction the moment any policy in its namespace selects it and
//     lists that direction in policyTypes — from then on the default in that direction is deny.
//   - A flow is allowed only when the source's EGRESS permits it AND the destination's INGRESS
//     permits it (a non-isolated side always permits).
//
// The semantics are specified by the table-driven suite in netpoleval_test.go, written before
// this engine (TDD) from the official docs' examples.
package netpoleval

import (
	"net"
	"sort"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PolicyRef identifies the NetworkPolicy responsible for a Verdict.
type PolicyRef struct {
	Namespace string
	Name      string
}

// PodInfo describes an in-cluster pod endpoint of a flow. Ports carries the pod's container
// ports and is only consulted when this pod is the DESTINATION, to resolve named policy ports
// (a policy port like `port: "http"` matches the target pod's container port with that name).
// IP is the pod's address (status.podIP) and is only consulted by ipBlock peers; empty means
// unknown, and an unknown IP never matches an ipBlock (conservative degraded mode).
type PodInfo struct {
	Namespace string
	Name      string
	Labels    map[string]string
	Ports     []corev1.ContainerPort
	IP        string
}

// Peer is one endpoint of a flow: exactly one of Pod (in-cluster) or IP (cluster-external, e.g.
// the graph's "internet" node) is set. Selector peers (podSelector/namespaceSelector) never match
// external Peers; ipBlock peers match external Peers by IP and pod Peers by PodInfo.IP when known
// (see ipBlockMatches).
type Peer struct {
	Pod *PodInfo
	IP  string
}

// Flow is a candidate connection: From → To on the destination's numeric Port and Protocol.
// Protocol is always explicit ("TCP"/"UDP"); named ports are a policy-side concept resolved
// against To's container ports, never a property of the flow itself.
type Flow struct {
	From     Peer
	To       Peer
	Port     int32
	Protocol corev1.Protocol
}

// Verdict is the evaluation result for one Flow. Policy attribution (feeds NetworkFlow.policy in
// the ScanReport contract):
//
//   - Allowed with Policy == nil: neither side is isolated — default allow, no policy involved.
//   - Allowed with Policy != nil: the policy whose rule matched. When both directions were
//     isolated and matched, the ingress-side (destination) policy is preferred — the graph is
//     destination-centric. Ties (multiple matching policies on the same side) resolve to the
//     first by (namespace, name) sort.
//   - Denied: the policy that switched the default to deny on the side that denied; the egress
//     (source) side is evaluated first. Among multiple isolating policies, one with zero rules in
//     the denied direction (a "pure default-deny") is preferred over policies that merely
//     activated isolation as a side effect; remaining ties resolve by (namespace, name) sort.
type Verdict struct {
	Allowed bool
	Policy  *PolicyRef
}

// implicitNameLabel is the namespace label the API server guarantees since 1.22; New injects it
// so namespaceSelector-by-name works even on hand-built fixtures.
const implicitNameLabel = "kubernetes.io/metadata.name"

// direction selects which side of a policy (ingress rules vs egress rules) is being evaluated.
type direction int

const (
	dirIngress direction = iota
	dirEgress
)

// Evaluator holds an indexed view of the cluster's NetworkPolicies and Namespaces, built once per
// snapshot and queried once per candidate flow.
type Evaluator struct {
	// policies is sorted by (namespace, name) so every attribution tie-break in Verdict is
	// deterministic regardless of API list order.
	policies []networkingv1.NetworkPolicy
	// nsLabels maps namespace name → labels, with implicitNameLabel injected.
	nsLabels map[string]map[string]string
}

// New builds an Evaluator from a snapshot's NetworkPolicies and Namespaces.
func New(policies []networkingv1.NetworkPolicy, namespaces []corev1.Namespace) *Evaluator {
	sorted := make([]networkingv1.NetworkPolicy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Namespace != sorted[j].Namespace {
			return sorted[i].Namespace < sorted[j].Namespace
		}
		return sorted[i].Name < sorted[j].Name
	})

	nsLabels := make(map[string]map[string]string, len(namespaces))
	for _, ns := range namespaces {
		lbls := make(map[string]string, len(ns.Labels)+1)
		for k, v := range ns.Labels {
			lbls[k] = v
		}
		lbls[implicitNameLabel] = ns.Name
		nsLabels[ns.Name] = lbls
	}

	return &Evaluator{policies: sorted, nsLabels: nsLabels}
}

// Eval returns the Verdict for one candidate flow: allowed only if the source's egress AND the
// destination's ingress permit it. See Verdict for the policy-attribution rules.
func (e *Evaluator) Eval(f Flow) Verdict {
	var egressMatch, ingressMatch *PolicyRef

	if f.From.Pod != nil {
		match, denier := e.evalDirection(f.From.Pod, f.To, dirEgress, f)
		if denier != nil {
			return Verdict{Allowed: false, Policy: denier}
		}
		egressMatch = match
	}
	if f.To.Pod != nil {
		match, denier := e.evalDirection(f.To.Pod, f.From, dirIngress, f)
		if denier != nil {
			return Verdict{Allowed: false, Policy: denier}
		}
		ingressMatch = match
	}

	if ingressMatch != nil {
		return Verdict{Allowed: true, Policy: ingressMatch}
	}
	if egressMatch != nil {
		return Verdict{Allowed: true, Policy: egressMatch}
	}
	return Verdict{Allowed: true, Policy: nil}
}

// evalDirection evaluates one side of the flow: subject is the pod whose ingress (dir=dirIngress)
// or egress (dir=dirEgress) is under evaluation, remote is the other endpoint. Returns exactly
// one of:
//
//	(nil, nil)       subject not isolated in this direction — side permits by default
//	(match, nil)     isolated and a rule matched — side permits, match is the matching policy
//	(nil, denier)    isolated and nothing matched — side denies, denier per Verdict's rules
func (e *Evaluator) evalDirection(subject *PodInfo, remote Peer, dir direction, f Flow) (match, denier *PolicyRef) {
	var isolating []networkingv1.NetworkPolicy
	for _, np := range e.policies {
		if np.Namespace != subject.Namespace {
			continue
		}
		if !appliesTo(np.Spec, dir) {
			continue
		}
		if !selectorMatches(&np.Spec.PodSelector, subject.Labels) {
			continue
		}
		isolating = append(isolating, np)
	}
	if len(isolating) == 0 {
		return nil, nil
	}

	for _, np := range isolating {
		for _, rule := range rulesOf(np, dir) {
			if e.peerListMatches(rule.peers, remote, np.Namespace) && portsMatch(rule.ports, f) {
				return &PolicyRef{Namespace: np.Namespace, Name: np.Name}, nil
			}
		}
	}

	// Denied: prefer a "pure default-deny" (zero rules in this direction) for attribution;
	// isolating is already (namespace, name)-sorted so the first hit is the deterministic pick.
	for _, np := range isolating {
		if len(rulesOf(np, dir)) == 0 {
			return nil, &PolicyRef{Namespace: np.Namespace, Name: np.Name}
		}
	}
	return nil, &PolicyRef{Namespace: isolating[0].Namespace, Name: isolating[0].Name}
}

// appliesTo reports whether the policy isolates pods in the given direction, implementing the
// API's policyTypes defaulting: when omitted, Ingress is ALWAYS assumed and Egress is assumed
// only if egress rules exist — the classic "egress-only policy also denies all ingress" gotcha.
// (The API server materializes this defaulting at admission; implementing it here keeps the
// engine correct on hand-built fixtures too.)
func appliesTo(spec networkingv1.NetworkPolicySpec, dir direction) bool {
	if len(spec.PolicyTypes) > 0 {
		for _, t := range spec.PolicyTypes {
			if (dir == dirIngress && t == networkingv1.PolicyTypeIngress) ||
				(dir == dirEgress && t == networkingv1.PolicyTypeEgress) {
				return true
			}
		}
		return false
	}
	if dir == dirIngress {
		return true
	}
	return len(spec.Egress) > 0
}

// ruleView unifies ingress (From) and egress (To) rules so evalDirection has one code path.
type ruleView struct {
	peers []networkingv1.NetworkPolicyPeer
	ports []networkingv1.NetworkPolicyPort
}

func rulesOf(np networkingv1.NetworkPolicy, dir direction) []ruleView {
	if dir == dirIngress {
		rules := make([]ruleView, 0, len(np.Spec.Ingress))
		for _, r := range np.Spec.Ingress {
			rules = append(rules, ruleView{peers: r.From, ports: r.Ports})
		}
		return rules
	}
	rules := make([]ruleView, 0, len(np.Spec.Egress))
	for _, r := range np.Spec.Egress {
		rules = append(rules, ruleView{peers: r.To, ports: r.Ports})
	}
	return rules
}

// peerListMatches reports whether the remote endpoint matches a rule's from/to list. An empty
// list matches ALL endpoints (the "rule with ports but no from" form); otherwise peers are OR'd.
func (e *Evaluator) peerListMatches(peers []networkingv1.NetworkPolicyPeer, remote Peer, policyNamespace string) bool {
	if len(peers) == 0 {
		return true
	}
	for _, p := range peers {
		if e.peerMatches(p, remote, policyNamespace) {
			return true
		}
	}
	return false
}

// peerMatches evaluates a single peer. ipBlock peers match only external endpoints; selector
// peers match only pod endpoints. Within a selector peer, namespaceSelector and podSelector are
// AND'd; a nil namespaceSelector scopes the peer to the policy's own namespace, and a nil
// podSelector matches every pod (in the selected namespaces).
func (e *Evaluator) peerMatches(p networkingv1.NetworkPolicyPeer, remote Peer, policyNamespace string) bool {
	if p.IPBlock != nil {
		return ipBlockMatches(p.IPBlock, remote)
	}
	if remote.Pod == nil {
		return false
	}
	if p.NamespaceSelector == nil {
		if remote.Pod.Namespace != policyNamespace {
			return false
		}
	} else if !selectorMatches(p.NamespaceSelector, e.namespaceLabels(remote.Pod.Namespace)) {
		return false
	}
	if p.PodSelector != nil && !selectorMatches(p.PodSelector, remote.Pod.Labels) {
		return false
	}
	return true
}

// namespaceLabels returns the evaluator's label view of a namespace. A namespace absent from the
// snapshot still gets its implicit name label — the API guarantees the label exists on every
// namespace, so matching by name must not silently fail.
func (e *Evaluator) namespaceLabels(name string) map[string]string {
	if lbls, ok := e.nsLabels[name]; ok {
		return lbls
	}
	return map[string]string{implicitNameLabel: name}
}

// ipBlockMatches reports whether the remote endpoint's IP falls inside the block's CIDR and
// outside every except range. For pod endpoints the pod's own IP (PodInfo.IP) is used — pod→pod
// packets carry the pod IP without SNAT on mainstream CNIs, which is the semantics the
// policy-assistant cross-validation corpus pins down; a pod with unknown IP never matches
// (conservative). Unparseable CIDRs/IPs are treated as non-matching — additive semantics mean a
// dropped rule can only under-allow, never wrongly allow.
func ipBlockMatches(block *networkingv1.IPBlock, remote Peer) bool {
	addr := remote.IP
	if remote.Pod != nil {
		addr = remote.Pod.IP
	}
	if addr == "" {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	_, cidr, err := net.ParseCIDR(block.CIDR)
	if err != nil || !cidr.Contains(ip) {
		return false
	}
	for _, except := range block.Except {
		_, exNet, err := net.ParseCIDR(except)
		if err == nil && exNet.Contains(ip) {
			return false
		}
	}
	return true
}

// portsMatch reports whether the flow's port/protocol matches a rule's port list. An empty list
// matches all ports. Numeric ports match exactly or via [port, endPort] inclusive ranges; named
// (string) ports resolve against the DESTINATION pod's container ports by name, requiring the
// container port's protocol and number to match the flow. Policy port protocol defaults to TCP.
func portsMatch(ports []networkingv1.NetworkPolicyPort, f Flow) bool {
	if len(ports) == 0 {
		return true
	}
	flowProto := f.Protocol
	if flowProto == "" {
		flowProto = corev1.ProtocolTCP
	}
	for _, p := range ports {
		proto := corev1.ProtocolTCP
		if p.Protocol != nil {
			proto = *p.Protocol
		}
		if proto != flowProto {
			continue
		}
		if p.Port == nil {
			return true
		}
		switch p.Port.Type {
		case intstr.Int:
			port := p.Port.IntVal
			if p.EndPort != nil {
				if f.Port >= port && f.Port <= *p.EndPort {
					return true
				}
			} else if f.Port == port {
				return true
			}
		case intstr.String:
			if namedPortResolves(p.Port.StrVal, proto, f) {
				return true
			}
		}
	}
	return false
}

// namedPortResolves reports whether the destination pod exposes a container port with the given
// name whose protocol and number match the flow. External destinations can never resolve a named
// port.
func namedPortResolves(name string, proto corev1.Protocol, f Flow) bool {
	if f.To.Pod == nil {
		return false
	}
	for _, cp := range f.To.Pod.Ports {
		if cp.Name != name {
			continue
		}
		cpProto := cp.Protocol
		if cpProto == "" {
			cpProto = corev1.ProtocolTCP
		}
		if cpProto == proto && cp.ContainerPort == f.Port {
			return true
		}
	}
	return false
}

// selectorMatches evaluates a metav1.LabelSelector against a label set via the apimachinery
// helper, which handles matchLabels AND matchExpressions and treats the empty selector as
// match-everything (exactly the NetworkPolicy semantics for `podSelector: {}`).
func selectorMatches(ls *metav1.LabelSelector, lbls map[string]string) bool {
	sel, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return false
	}
	return sel.Matches(labels.Set(lbls))
}
