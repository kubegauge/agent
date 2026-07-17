// Ferramenta de validação cruzada do M5 (Aurora Shield): gera o corpus golden de
// testdata/policy_assistant_corpus.json.gz consumido por netpoleval/crossvalidation_test.go.
//
// Ela usa o matcher do policy-assistant (kubernetes-sigs/network-policy-api, ex-Cyclonus) como
// oráculo: para cada caso do gerador oficial de policies (filtrado para ações só-CreatePolicy,
// i.e. variantes semânticas puras sem mutação de cluster), avalia todos os flows de uma matriz
// de tráfego fixa e grava o veredito allowed/denied. O teste do collector reavalia os mesmos
// flows com o nosso engine e compara.
//
// Como regenerar o corpus (o clone é gitignored; commit pinado no meta.commit do corpus):
//
//	git clone --depth 1 https://github.com/kubernetes-sigs/network-policy-api.git policy-assistant-src
//	go mod tidy
//	go run . > corpus.json && gzip -9 -c corpus.json > ../../internal/netpoleval/testdata/policy_assistant_corpus.json.gz
//
// Decisões que evitam falsos positivos de divergência:
//
//   - ipBlock: o matcher deles casa ipBlock contra o IP de QUALQUER peer, inclusive pods; o nosso
//     engine (por design do produto — Peer de pod não tem IP) escopa ipBlock a endpoints externos,
//     como a doc oficial. Os IPs sintéticos dos pods (10.96.0.0/16) são disjuntos dos CIDRs que o
//     gerador constrói ao redor do podIP (192.168.100.0/24), então ipBlock nunca casa pod interno
//     em nenhum dos dois engines e a comparação fica justa. IPs externos são escolhidos dentro do
//     CIDR, dentro do except e fora, para exercitar ipBlock de verdade.
//   - Named ports: espelha o probe sintético deles — para destino pod, cada container port vira um
//     probe com (porta, protocolo, nome); portas não servidas (79/82/7981) e destinos externos
//     têm nome vazio.
//   - Labels de namespace: {"ns": <nome>} + kubernetes.io/metadata.name injetado, como o API server.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/network-policy-api/policy-assistant/pkg/generator"
	"sigs.k8s.io/network-policy-api/policy-assistant/pkg/matcher"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// podIP é a semente dos CIDRs de ipBlock do gerador (MakeCIDRFromZeroes → 192.168.100.0/24 e /28).
const podIP = "192.168.100.5"

type corpusPort struct {
	Name     string `json:"name"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

type corpusPod struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	IP        string            `json:"ip"`
	Ports     []corpusPort      `json:"ports"`
}

type corpusNamespace struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// corpusFlow referencia endpoints por chave: "ns/pod" para pods, "ip:<addr>" para externos.
type corpusFlow struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
	PortName string `json:"portName,omitempty"`
}

type corpusCase struct {
	Description string            `json:"description"`
	Policies    []json.RawMessage `json:"policies"`
	// Verdicts[i] corresponde a flows[i]: 'A' = allowed, 'D' = denied.
	Verdicts string `json:"verdicts"`
}

type corpus struct {
	Meta       map[string]string `json:"meta"`
	Namespaces []corpusNamespace `json:"namespaces"`
	Pods       []corpusPod       `json:"pods"`
	Flows      []corpusFlow      `json:"flows"`
	Cases      []corpusCase      `json:"cases"`
}

func buildPods() []corpusPod {
	var pods []corpusPod
	for nsIdx, ns := range []string{"x", "y", "z"} {
		for podIdx, name := range []string{"a", "b", "c"} {
			var ports []corpusPort
			for _, proto := range []string{"TCP", "UDP", "SCTP"} {
				for _, port := range []int32{80, 81} {
					ports = append(ports, corpusPort{
						Name:     fmt.Sprintf("serve-%d-%s", port, strings.ToLower(proto)),
						Port:     port,
						Protocol: proto,
					})
				}
			}
			pods = append(pods, corpusPod{
				Namespace: ns,
				Name:      name,
				Labels:    map[string]string{"pod": name},
				IP:        fmt.Sprintf("10.96.%d.%d", nsIdx, podIdx+1),
				Ports:     ports,
			})
		}
	}
	return pods
}

// externalIPs: dentro do CIDR /24 (fora do except /28), dentro do except /28, e fora de tudo.
var externalIPs = []string{"192.168.100.100", "192.168.100.5", "8.8.8.8"}

// unservedProbes exercita endPort ranges e named ports não resolvíveis (nenhum pod serve).
var unservedProbes = []corpusPort{
	{Port: 79, Protocol: "TCP"}, {Port: 79, Protocol: "UDP"},
	{Port: 82, Protocol: "TCP"}, {Port: 82, Protocol: "UDP"},
	{Port: 7981, Protocol: "TCP"}, {Port: 7981, Protocol: "UDP"},
}

var externalDestProbes = []corpusPort{
	{Port: 80, Protocol: "TCP"}, {Port: 80, Protocol: "UDP"},
	{Port: 81, Protocol: "TCP"}, {Port: 81, Protocol: "UDP"},
	{Port: 79, Protocol: "TCP"},
}

func buildFlows(pods []corpusPod) []corpusFlow {
	var endpoints []string
	for _, p := range pods {
		endpoints = append(endpoints, p.Namespace+"/"+p.Name)
	}
	for _, ip := range externalIPs {
		endpoints = append(endpoints, "ip:"+ip)
	}
	podByKey := make(map[string]corpusPod, len(pods))
	for _, p := range pods {
		podByKey[p.Namespace+"/"+p.Name] = p
	}

	var flows []corpusFlow
	for _, from := range endpoints {
		for _, to := range endpoints {
			fromExt := strings.HasPrefix(from, "ip:")
			toExt := strings.HasPrefix(to, "ip:")
			if fromExt && toExt {
				continue // externo→externo: nenhuma policy se aplica, sem valor
			}
			if toExt {
				for _, pr := range externalDestProbes {
					flows = append(flows, corpusFlow{From: from, To: to, Port: pr.Port, Protocol: pr.Protocol})
				}
				continue
			}
			dest := podByKey[to]
			for _, cp := range dest.Ports {
				flows = append(flows, corpusFlow{From: from, To: to, Port: cp.Port, Protocol: cp.Protocol, PortName: cp.Name})
			}
			for _, pr := range unservedProbes {
				flows = append(flows, corpusFlow{From: from, To: to, Port: pr.Port, Protocol: pr.Protocol})
			}
		}
	}
	return flows
}

func trafficPeer(key string, podByKey map[string]corpusPod) *matcher.TrafficPeer {
	if ip, ok := strings.CutPrefix(key, "ip:"); ok {
		return &matcher.TrafficPeer{IP: ip}
	}
	pod := podByKey[key]
	return &matcher.TrafficPeer{
		IP: pod.IP,
		Internal: &matcher.InternalPeer{
			Namespace: pod.Namespace,
			PodLabels: pod.Labels,
			NamespaceLabels: map[string]string{
				"ns":                          pod.Namespace,
				"kubernetes.io/metadata.name": pod.Namespace,
			},
		},
	}
}

// collectPolicies devolve as policies de um caso composto apenas por ações CreatePolicy, ou
// ok=false quando o caso muta cluster (update/delete/pods/namespaces) ou repete (ns, name).
func collectPolicies(tc *generator.TestCase) (policies []*networkingv1.NetworkPolicy, ok bool) {
	seen := map[string]bool{}
	for _, step := range tc.Steps {
		for _, action := range step.Actions {
			if action.CreatePolicy == nil {
				return nil, false
			}
			p := action.CreatePolicy.Policy
			key := p.Namespace + "/" + p.Name
			if seen[key] {
				return nil, false
			}
			seen[key] = true
			policies = append(policies, p)
		}
	}
	return policies, len(policies) > 0
}

func main() {
	pods := buildPods()
	flows := buildFlows(pods)
	podByKey := make(map[string]corpusPod, len(pods))
	for _, p := range pods {
		podByKey[p.Namespace+"/"+p.Name] = p
	}

	gen := generator.NewTestCaseGenerator(false, podIP, []string{"x", "y", "z"}, nil, nil)
	all := gen.GenerateAllTestCases()

	var cases []corpusCase
	seenPolicySets := map[string]bool{}
	skippedMutation, skippedDup := 0, 0
	allowedTotal, deniedTotal := 0, 0

	for _, tc := range all {
		policies, ok := collectPolicies(tc)
		if !ok {
			skippedMutation++
			continue
		}

		var rawPolicies []json.RawMessage
		var setKey []string
		for _, p := range policies {
			raw, err := json.Marshal(p)
			if err != nil {
				panic(err)
			}
			rawPolicies = append(rawPolicies, raw)
			setKey = append(setKey, string(raw))
		}
		sort.Strings(setKey)
		dedupe := strings.Join(setKey, "|")
		if seenPolicySets[dedupe] {
			skippedDup++
			continue
		}
		seenPolicySets[dedupe] = true

		oracle := matcher.BuildNetworkPolicies(false, policies)
		verdicts := make([]byte, len(flows))
		for i, f := range flows {
			traffic := &matcher.Traffic{
				Source:           trafficPeer(f.From, podByKey),
				Destination:      trafficPeer(f.To, podByKey),
				ResolvedPort:     int(f.Port),
				ResolvedPortName: f.PortName,
				Protocol:         corev1.Protocol(f.Protocol),
			}
			if oracle.IsTrafficAllowed(traffic).IsAllowed() {
				verdicts[i] = 'A'
				allowedTotal++
			} else {
				verdicts[i] = 'D'
				deniedTotal++
			}
		}
		cases = append(cases, corpusCase{
			Description: tc.Description,
			Policies:    rawPolicies,
			Verdicts:    string(verdicts),
		})
	}

	commit := "unknown"
	if out, err := exec.Command("git", "-C", "policy-assistant-src", "rev-parse", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(out))
	}

	namespaces := []corpusNamespace{
		{Name: "x", Labels: map[string]string{"ns": "x"}},
		{Name: "y", Labels: map[string]string{"ns": "y"}},
		{Name: "z", Labels: map[string]string{"ns": "z"}},
	}

	c := corpus{
		Meta: map[string]string{
			"source":      "https://github.com/kubernetes-sigs/network-policy-api (cmd/policy-assistant)",
			"commit":      commit,
			"generatedBy": "collector/tools/policy-assistant-xval",
			"generatedAt": time.Now().UTC().Format(time.RFC3339),
			"podIP":       podIP,
		},
		Namespaces: namespaces,
		Pods:       pods,
		Flows:      flows,
		Cases:      cases,
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(c); err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stderr, "generator cases: %d total | %d kept | %d skipped (mutation) | %d skipped (dup)\n",
		len(all), len(cases), skippedMutation, skippedDup)
	fmt.Fprintf(os.Stderr, "flows per case: %d | verdicts: %d allowed, %d denied\n",
		len(flows), allowedTotal, deniedTotal)
}
