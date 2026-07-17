// Validação cruzada do engine M5 (Aurora Shield): reavalia o corpus golden gerado pelo matcher do
// policy-assistant (kubernetes-sigs/network-policy-api, ex-Cyclonus) e exige veredito idêntico.
// Corpus e decisões de modelagem: collector/tools/policy-assistant-xval/main.go.
package netpoleval

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

type corpusFlow struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

type corpusCase struct {
	Description string            `json:"description"`
	Policies    []json.RawMessage `json:"policies"`
	Verdicts    string            `json:"verdicts"`
}

type corpusFile struct {
	Meta       map[string]string `json:"meta"`
	Namespaces []corpusNamespace `json:"namespaces"`
	Pods       []corpusPod       `json:"pods"`
	Flows      []corpusFlow      `json:"flows"`
	Cases      []corpusCase      `json:"cases"`
}

func loadCorpus(t *testing.T) *corpusFile {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "policy_assistant_corpus.json.gz"))
	if err != nil {
		t.Fatalf("abrindo corpus: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("descomprimindo corpus: %v", err)
	}
	defer gz.Close()
	var c corpusFile
	if err := json.NewDecoder(gz).Decode(&c); err != nil {
		t.Fatalf("decodificando corpus: %v", err)
	}
	return &c
}

// corpusPeer converte a chave de endpoint do corpus ("ns/pod" ou "ip:<addr>") em um Peer.
func corpusPeer(t *testing.T, key string, pods map[string]*PodInfo) Peer {
	t.Helper()
	if ip, ok := strings.CutPrefix(key, "ip:"); ok {
		return Peer{IP: ip}
	}
	pod, ok := pods[key]
	if !ok {
		t.Fatalf("corpus referencia pod desconhecido %q", key)
	}
	return Peer{Pod: pod}
}

func TestCrossValidationAgainstPolicyAssistant(t *testing.T) {
	c := loadCorpus(t)

	// Guardas contra corpus vazio/corrompido passando em silêncio.
	if len(c.Cases) < 200 {
		t.Fatalf("corpus suspeito: só %d casos (esperado 200+)", len(c.Cases))
	}
	if len(c.Flows) == 0 {
		t.Fatal("corpus sem flows")
	}

	namespaces := make([]corev1.Namespace, 0, len(c.Namespaces))
	for _, ns := range c.Namespaces {
		namespaces = append(namespaces, corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns.Name, Labels: ns.Labels},
		})
	}

	pods := make(map[string]*PodInfo, len(c.Pods))
	for _, p := range c.Pods {
		ports := make([]corev1.ContainerPort, 0, len(p.Ports))
		for _, cp := range p.Ports {
			ports = append(ports, corev1.ContainerPort{
				Name:          cp.Name,
				ContainerPort: cp.Port,
				Protocol:      corev1.Protocol(cp.Protocol),
			})
		}
		pods[p.Namespace+"/"+p.Name] = &PodInfo{
			Namespace: p.Namespace,
			Name:      p.Name,
			Labels:    p.Labels,
			Ports:     ports,
			IP:        p.IP,
		}
	}

	flows := make([]Flow, 0, len(c.Flows))
	for _, f := range c.Flows {
		flows = append(flows, Flow{
			From:     corpusPeer(t, f.From, pods),
			To:       corpusPeer(t, f.To, pods),
			Port:     f.Port,
			Protocol: corev1.Protocol(f.Protocol),
		})
	}

	const maxDetailed = 15
	totalMismatches := 0
	affectedCases := 0

	for caseIdx, tc := range c.Cases {
		if len(tc.Verdicts) != len(flows) {
			t.Fatalf("caso %d (%q): %d vereditos para %d flows", caseIdx, tc.Description, len(tc.Verdicts), len(flows))
		}

		policies := make([]networkingv1.NetworkPolicy, 0, len(tc.Policies))
		for _, raw := range tc.Policies {
			var np networkingv1.NetworkPolicy
			if err := json.Unmarshal(raw, &np); err != nil {
				t.Fatalf("caso %d (%q): policy inválida: %v", caseIdx, tc.Description, err)
			}
			policies = append(policies, np)
		}

		ev := New(policies, namespaces)
		caseMismatches := 0
		for i, flow := range flows {
			want := tc.Verdicts[i] == 'A'
			got := ev.Eval(flow).Allowed
			if got != want {
				caseMismatches++
				totalMismatches++
				if totalMismatches <= maxDetailed {
					t.Errorf("caso %d (%q): flow %s → veredito %s, policy-assistant espera %s",
						caseIdx, tc.Description, describeFlow(c.Flows[i]), verdictName(got), verdictName(want))
				}
			}
		}
		if caseMismatches > 0 {
			affectedCases++
		}
	}

	if totalMismatches > 0 {
		t.Errorf("validação cruzada: %d divergências em %d/%d casos (detalhadas as %d primeiras; corpus: %s @ %s)",
			totalMismatches, affectedCases, len(c.Cases), maxDetailed, c.Meta["source"], c.Meta["commit"])
	}
}

func describeFlow(f corpusFlow) string {
	return fmt.Sprintf("%s→%s :%d/%s", f.From, f.To, f.Port, f.Protocol)
}

func verdictName(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "denied"
}
