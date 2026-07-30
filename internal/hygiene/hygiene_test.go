// hygiene_test.go guards how the public repo presents itself: this is the only KubeGauge repo
// outsiders read, so it stays English everywhere — code, comments, CI and chart — and carries no
// trace of the authoring toolchain. Deliberately conservative: it catches habit, not every slip.
package hygiene

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Everything a visitor reads. Markdown is already English and stays that way.
var scanned = map[string]bool{".go": true, ".yml": true, ".yaml": true, ".tpl": true, ".md": true}

// Files a visitor reads that carry no meaningful extension, so `scanned` would miss them.
var scannedNames = map[string]bool{
	"Dockerfile": true, "Makefile": true, ".gitignore": true, ".dockerignore": true,
}

// portugueseWords are unaccented Portuguese words with no English or Kubernetes homograph. The
// diacritic class below catches accented prose for free, so this list only has to cover what
// survives without accents — which is most of a sentence, since Portuguese function words rarely
// carry one. It caught roughly forty tracked lines the twelve-word version let through, including
// user-visible ones rendered by `helm template` and `kubectl get -o yaml`.
//
// Deliberately absent, because they collide with things this repo legitimately contains:
//
//	com, para, dos   -> ".com", English "para-", "DoS"
//	de, da, do, no, na, em, os, as, um, se, so, e, a, o, por
//	                 -> too short; homographs of English words or of base64/flag fragments
//	nova, era, valor, usa, ja
//	                 -> "supernova"/Nova, the English noun "era", English "valor", "USA", "JA"
//
// A word list never finishes and is not meant to: it raises the cost of habit, and the diacritic
// rule catches the rest.
var portugueseWords = []string{
	"acesso", "agora", "ainda", "antes", "apenas", "aplica", "aquela", "aquele", "arquivo",
	"arquivos", "ativou", "audite", "baixado", "baixar", "banco", "bloco", "campo", "campos",
	"caso", "casos", "cada", "carregar", "chave", "chaves", "claro", "consciente", "continha",
	"converte", "copiar", "copie", "corrompida", "corrompido", "criada", "criado", "das",
	"dentro", "depois", "desabilitada", "desabilitado", "deve", "devem", "deveria", "encontrado",
	"entao", "entre", "erro", "erros", "escaneado", "escaneia", "espera", "esperava", "essa",
	"esse", "esta", "estas", "este", "estes", "existir", "exporte", "externa", "externo",
	"externos", "falha", "falhas", "faz", "fazer", "feita", "feito", "fora", "habilitada",
	"habilitado", "identidade", "imagem", "imagens", "iniciar", "isso", "isto", "janela",
	"linha", "linhas", "lugar", "mais", "mas", "menos", "mesmo", "modo", "muito", "nada", "nao",
	"nenhum", "nenhuma", "nome", "nomes", "novo", "numero", "numeros", "nunca", "onde", "pela",
	"pelo", "pode", "podem", "porem", "porque", "precisa", "precisam", "primeiro", "protegida",
	"protegido", "publica", "publico", "quando", "que", "recursos", "reconhecida", "reconhecido",
	"recusar", "referencia", "regra", "retorna", "retornar", "rode", "rodou", "sao", "segundo",
	"sem", "sempre", "senha", "ser", "seu", "seus", "somente", "sua", "suas", "suportada",
	"suportado", "tabela", "tambem", "tem", "ter", "teste", "testes", "texto", "todas", "todos",
	"tudo", "uma", "umas", "uns", "ultimo", "usada", "usado", "usar", "vai", "vao", "valores",
	"vazia", "vazio", "velha", "velho", "veredito", "vereditos", "verifique",
}

var forbidden = []struct {
	name string
	re   *regexp.Regexp
}{
	// "cursor" is deliberately absent: Kubernetes list pagination legitimately uses the word.
	{"authoring-toolchain reference", regexp.MustCompile(`(?i)\b(claude|anthropic|copilot)\b`)},
	// A Portuguese diacritic is unambiguous in a Go/Kubernetes tree.
	{"Portuguese diacritic", regexp.MustCompile(`[ãõçáéíóúâêôàÃÕÇÁÉÍÓÚÂÊÔÀ]`)},
	{"Portuguese prose", regexp.MustCompile(`(?i)\b(` + strings.Join(portugueseWords, "|") + `)\b`)},
}

// TestGuardCatchesUnaccentedPortuguese tests the guard itself. Without it, the word list could be
// gutted back to a handful of entries and the repo scan would still pass, exactly as it did while
// forty tracked lines of unaccented Portuguese sat in the tree — some of them printed to operators
// by `helm template` and `kubectl get -o yaml`. These samples are real lines this repo shipped.
func TestGuardCatchesUnaccentedPortuguese(t *testing.T) {
	mustCatch := []string{
		"# serviceaccount.yaml — identidade read-only do agente.",
		"# Cache do banco de CVEs do trivy (baixado em runtime)",
		`echo "erro: exporte KG_API_KEY (rode 'make seed')"`,
		"// corrompido = miss, re-escaneia",
		`t.Fatal("esperava cache hit dentro do TTL")`,
		`name: "cluster sem Deployments"`,
		`t.Errorf("caso %d: flow %s, policy-assistant espera %s")`,
		`c := newDiskCache("") // dir vazio = cache desabilitado`,
	}
	for _, line := range mustCatch {
		caught := false
		for _, f := range forbidden {
			if f.re.MatchString(line) {
				caught = true
			}
		}
		if !caught {
			t.Errorf("guard let unaccented Portuguese through: %s", line)
		}
	}

	// The other half of a useful guard: English and Kubernetes vocabulary must survive it, or the
	// next person deletes the test instead of fixing their line.
	mustPass := []string{
		"// listAll pages through a List call (Limit/Continue) instead of one huge response.",
		"see support.stripe.com and example.com for the para-virtualized DoS mitigation",
		"// Nova and the modern era of valor: USA-only, semver-tagged, no-op",
		"resources: [nodes, namespaces, pods, serviceaccounts, services]",
		"// A denial-of-service (DoS) guard: the parameter is a no-op on this path.",
		"const maxAttempts = 5 // retry budget, then keep the report for later",
	}
	for _, line := range mustPass {
		for _, f := range forbidden {
			if m := f.re.FindString(line); m != "" {
				t.Errorf("guard false-positives on English (%q in %q)", m, line)
			}
		}
	}
}

func TestPublicRepoIsEnglishAndUnbranded(t *testing.T) {
	self, err := filepath.Abs("hygiene_test.go")
	if err != nil {
		t.Fatalf("resolving own path: %v", err)
	}

	walkErr := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !scanned[filepath.Ext(path)] && !scannedNames[d.Name()] {
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if abs == self {
			return nil // this file necessarily names the patterns it forbids
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, f := range forbidden {
				if m := f.re.FindString(line); m != "" {
					t.Errorf("%s:%d: %s (%q): %s", path, i+1, f.name, m, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking repo: %v", walkErr)
	}
}
