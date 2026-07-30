// network.go builds the real network graph (M5): flow candidates derived from Services ("who
// exposes which port to whom", PLAN-FASE-2.md §8) plus the external/internet node, with each
// candidate's verdict decided by the internal/netpoleval engine. Candidate model:
//
//   - For each Service with a selector, every workload in a non-system namespace is a candidate
//     SOURCE toward each of the Service's backends on each resolved target port. Services in
//     system namespaces still count as DESTINATIONS (the classic "does default-deny egress break
//     DNS?" flow to kube-dns is exactly the educational case we want on the graph), but system
//     workloads are never sources — they would only add noise.
//   - NodePort/LoadBalancer Services additionally get an ingress candidate from the internet node.
//   - Every non-system workload gets one egress candidate to the internet node on 443/TCP — the
//     canonical "can this thing reach out?" edge.
//
// Deriving candidates from Services is narrower than pairing arbitrary workloads, but it is NOT
// bounded: the east-west set is services x backends x ports x every non-system workload, which on
// a cluster with a thousand Services and a few thousand workloads is millions of flows — each one
// evaluated, retained, serialized and gzipped, against a 1Gi pod limit and a 5 MB server-side
// payload cap. The package used to claim otherwise; MaxFlows below is what actually bounds it.
// Emission is ordered by value so a truncated graph still tells the exposure story: internet
// ingress first, then each workload's egress candidate, then east-west.
package report

import (
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kubegauge/agent/internal/netpoleval"
	"github.com/kubegauge/agent/internal/snapshot"
)

const (
	internetNodeID = "external/internet"
	// internetProxyIP is the representative address the internet node presents to netpoleval:
	// ipBlock rules are evaluated against it. 203.0.113.1 sits in TEST-NET-3 (RFC 5737), a
	// documentation range no cluster CIDR should overlap — so "allow 0.0.0.0/0" matches it and
	// "allow 10.0.0.0/8" does not, which is exactly the verdict a real internet peer would get.
	internetProxyIP = "203.0.113.1"
	// internetEgressPort: the single representative egress candidate per workload (HTTPS).
	internetEgressPort = 443
)

// MaxFlows caps how many flows one report carries. The east-west candidate set grows with
// services x backends x ports x workloads, so on a large cluster it is effectively unbounded: left
// alone it OOMs the agent against the chart's 1Gi limit, or produces a payload the API rejects
// (5 MB decoded), which means that cluster never reports at all. 5k flows is a graph no human
// reads to the end and roughly 600 KB of JSON. Beyond it the graph is a sample, in priority order
// (see the package doc): the agent logs when a report comes back at the cap.
const MaxFlows = 5000

// networkSystemNamespaces mirrors internal/checks's systemNamespaces (an import here would be a
// cycle: checks imports report). Workloads in these namespaces are never flow SOURCES; see the
// package doc comment for why their Services remain valid destinations.
var networkSystemNamespaces = map[string]bool{
	"kube-system":        true,
	"kube-public":        true,
	"kube-node-lease":    true,
	"local-path-storage": true,
}

// netWorkload pairs a WorkloadSource with its graph node id and its netpoleval endpoint view.
type netWorkload struct {
	id   string
	src  WorkloadSource
	info *netpoleval.PodInfo
}

// BuildNetwork derives the network graph from a snapshot: nodes are workloads participating in at
// least one flow (plus the external/internet node), flows are the Service-derived candidates
// described in the package doc comment, each evaluated by netpoleval. Output is deterministic:
// nodes sorted by id with the internet node last (the mock's convention), flows sorted by
// (from, to, port, protocol).
func BuildNetwork(snap *snapshot.Snapshot) ([]NetworkNode, []NetworkFlow) {
	eval := netpoleval.New(snap.NetworkPolicies, snap.Namespaces)

	var workloads []netWorkload
	for _, ws := range WorkloadSources(snap) {
		var ports []corev1.ContainerPort
		for _, c := range ws.Spec.Containers {
			ports = append(ports, c.Ports...)
		}
		workloads = append(workloads, netWorkload{
			id:  ws.Namespace + "/" + ws.Name,
			src: ws,
			info: &netpoleval.PodInfo{
				Namespace: ws.Namespace, Name: ws.Name, Labels: ws.Labels, Ports: ports,
				IP: representativePodIP(ws, snap.Pods),
			},
		})
	}

	var clients []netWorkload
	for _, w := range workloads {
		if !networkSystemNamespaces[w.src.Namespace] {
			clients = append(clients, w)
		}
	}

	type flowKey struct {
		from, to string
		port     int32
		proto    corev1.Protocol
	}
	seen := map[flowKey]bool{}
	nodeSeen := map[string]bool{}
	flows := []NetworkFlow{}
	internetPeer := netpoleval.Peer{IP: internetProxyIP}

	// addFlow reports whether there is budget left to keep going: every caller must stop when it
	// returns false, or the loops would keep paying the O(services x workloads) cost for flows
	// nobody will emit.
	addFlow := func(fromID string, from netpoleval.Peer, toID string, to netpoleval.Peer, port int32, proto corev1.Protocol) bool {
		if len(flows) >= MaxFlows {
			return false
		}
		if fromID == toID {
			return true
		}
		key := flowKey{from: fromID, to: toID, port: port, proto: proto}
		if seen[key] {
			return true
		}
		seen[key] = true

		verdict := "denied"
		var policy *string
		v := eval.Eval(netpoleval.Flow{From: from, To: to, Port: port, Protocol: proto})
		if v.Allowed {
			verdict = "allowed"
		}
		if v.Policy != nil {
			ref := v.Policy.Namespace + "/" + v.Policy.Name
			policy = &ref
		}
		flows = append(flows, NetworkFlow{From: fromID, To: toID, Port: int(port), Protocol: string(proto), Verdict: verdict, Policy: policy})
		nodeSeen[fromID] = true
		nodeSeen[toID] = true
		return len(flows) < MaxFlows
	}

	endpoints := serviceEndpoints(snap.Services, workloads)

	// Priority 1: what the internet can reach. A truncated graph that lost these would hide the
	// finding that matters most.
	for _, ep := range endpoints {
		if !ep.exposed {
			continue
		}
		if !addFlow(internetNodeID, internetPeer, ep.backend.id, netpoleval.Peer{Pod: ep.backend.info}, ep.port, ep.proto) {
			break
		}
	}

	// Priority 2: one egress candidate per workload — "can this thing reach out?".
	for _, c := range clients {
		if !addFlow(c.id, netpoleval.Peer{Pod: c.info}, internetNodeID, internetPeer, internetEgressPort, corev1.ProtocolTCP) {
			break
		}
	}

	// Priority 3: east-west. This is the set that explodes, so it spends whatever budget is left.
eastWest:
	for _, ep := range endpoints {
		for _, c := range clients {
			if !addFlow(c.id, netpoleval.Peer{Pod: c.info}, ep.backend.id, netpoleval.Peer{Pod: ep.backend.info}, ep.port, ep.proto) {
				break eastWest
			}
		}
	}

	nodes := []NetworkNode{}
	for _, w := range workloads {
		if nodeSeen[w.id] {
			nodes = append(nodes, NetworkNode{ID: w.id, Label: w.src.Name, Namespace: w.src.Namespace, Kind: "pod"})
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	if nodeSeen[internetNodeID] {
		nodes = append(nodes, NetworkNode{ID: internetNodeID, Label: "Internet", Namespace: "external", Kind: "external"})
	}

	sort.Slice(flows, func(i, j int) bool {
		a, b := flows[i], flows[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Protocol < b.Protocol
	})
	return nodes, flows
}

// svcEndpoint is one resolved (Service backend, port) pair: the destination side of a flow
// candidate, computed once so the two phases that need it do not re-run the
// O(services x workloads) selector matching.
type svcEndpoint struct {
	backend netWorkload
	port    int32
	proto   corev1.Protocol
	exposed bool // NodePort/LoadBalancer: also reachable from the internet node
}

// serviceEndpoints resolves every Service to its backends and target ports, in a deterministic
// order (services sorted by namespace/name) so truncation cuts the same candidates on every scan
// of an unchanged cluster.
func serviceEndpoints(services []corev1.Service, workloads []netWorkload) []svcEndpoint {
	sorted := make([]corev1.Service, len(services))
	copy(sorted, services)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Namespace != sorted[j].Namespace {
			return sorted[i].Namespace < sorted[j].Namespace
		}
		return sorted[i].Name < sorted[j].Name
	})

	var out []svcEndpoint
	for _, svc := range sorted {
		if len(svc.Spec.Selector) == 0 {
			// Selector-less Services (manual Endpoints, e.g. default/kubernetes) have no pod
			// backends to point a flow at.
			continue
		}
		exposed := svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeLoadBalancer
		for _, backend := range workloads {
			if backend.src.Namespace != svc.Namespace || !selectorCovers(svc.Spec.Selector, backend.src.Labels) {
				continue
			}
			for _, sp := range svc.Spec.Ports {
				proto := sp.Protocol
				if proto == "" {
					proto = corev1.ProtocolTCP
				}
				port, ok := resolveTargetPort(sp, proto, backend.info.Ports)
				if !ok {
					continue
				}
				out = append(out, svcEndpoint{backend: backend, port: port, proto: proto, exposed: exposed})
			}
		}
	}
	return out
}

// representativePodIP resolves the IP a workload's packets actually carry, so netpoleval can
// evaluate ipBlock peers against pod endpoints (semantics pinned by the policy-assistant
// cross-validation corpus). Bare Pods use their own status.podIP; controllers use the live pod
// with the lexicographically smallest name among those covered by the template labels
// (deterministic across scans). Empty result = unknown IP, and netpoleval degrades to never
// matching ipBlock for that endpoint — under-allowing, never wrongly allowing.
func representativePodIP(ws WorkloadSource, pods []corev1.Pod) string {
	ip, bestName := "", ""
	for i := range pods {
		p := &pods[i]
		if p.Namespace != ws.Namespace || p.Status.PodIP == "" {
			continue
		}
		if ws.Kind == "Pod" {
			if p.Name == ws.Name {
				return p.Status.PodIP
			}
			continue
		}
		if len(ws.Labels) == 0 || !selectorCovers(ws.Labels, p.Labels) {
			continue
		}
		if bestName == "" || p.Name < bestName {
			ip, bestName = p.Status.PodIP, p.Name
		}
	}
	return ip
}

// selectorCovers implements Service-selector matching: every selector key/value must be present
// in the pod labels (equality-based match, the only form spec.selector supports).
func selectorCovers(selector, podLabels map[string]string) bool {
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// resolveTargetPort resolves a ServicePort to the numeric container port a flow actually targets:
// named targetPorts resolve against the backend's container ports (matching name AND protocol,
// like kube-proxy does per-pod); an unset targetPort defaults to the service port (the API
// server's own defaulting, re-implemented so hand-built fixtures behave like real objects). A
// named port that doesn't resolve on this backend yields no candidate at all — we'd rather omit a
// flow than invent a port number.
func resolveTargetPort(sp corev1.ServicePort, proto corev1.Protocol, backendPorts []corev1.ContainerPort) (int32, bool) {
	if sp.TargetPort.Type == intstr.String {
		for _, cp := range backendPorts {
			cpProto := cp.Protocol
			if cpProto == "" {
				cpProto = corev1.ProtocolTCP
			}
			if cp.Name == sp.TargetPort.StrVal && cpProto == proto {
				return cp.ContainerPort, true
			}
		}
		return 0, false
	}
	if sp.TargetPort.IntVal != 0 {
		return sp.TargetPort.IntVal, true
	}
	return sp.Port, true
}
