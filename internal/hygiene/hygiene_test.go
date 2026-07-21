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

var forbidden = []struct {
	name string
	re   *regexp.Regexp
}{
	// "cursor" is deliberately absent: Kubernetes list pagination legitimately uses the word.
	{"authoring-toolchain reference", regexp.MustCompile(`(?i)\b(claude|anthropic|copilot)\b`)},
	// A word-list never finishes; a Portuguese diacritic is unambiguous in a Go/Kubernetes tree.
	{"Portuguese diacritic", regexp.MustCompile(`[ãõçáéíóúâêôàÃÕÇÁÉÍÓÚÂÊÔÀ]`)},
	// Unaccented Portuguese with no English or Kubernetes homograph. "com", "para" and "dos" are
	// deliberately absent: they collide with ".com", English "para-" and "DoS".
	{"Portuguese prose", regexp.MustCompile(`(?i)\b(nao|entao|apenas|arquivo|imagem|precisa|consciente|publica|nenhum|antes|depois|porque)\b`)},
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
