// versions_test.go covers KG-VU-001 (Kubernetes version support window, versions.go). The verdict
// is a pure function of snapshot.ServerVersion plus a clock, so every case pins "now" via the
// check's injectable now field — the EOL table itself holds fixed, published dates and is not
// stubbed.
package checks

import (
	"reflect"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/version"

	"github.com/kubegauge/agent/internal/snapshot"
)

func TestKubernetesVersionSupportCheck(t *testing.T) {
	// 2026-07-13: 1.33 (EOL 2026-06-28) just left the support window; 1.34 (EOL 2026-10-28) is
	// supported and more than 90 days away from EOL.
	base := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name          string
		server        *version.Info
		now           time.Time
		wantStatus    string
		wantResources []string
	}{
		{
			name:          "server version ausente",
			server:        nil,
			now:           base,
			wantStatus:    "info",
			wantResources: []string{},
		},
		{
			name:          "minor após o EOL",
			server:        &version.Info{Major: "1", Minor: "33", GitVersion: "v1.33.2"},
			now:           base,
			wantStatus:    "fail",
			wantResources: []string{"cluster/v1.33.2"},
		},
		{
			name:          "minor suportada longe do EOL",
			server:        &version.Info{Major: "1", Minor: "35", GitVersion: "v1.35.0"},
			now:           base,
			wantStatus:    "pass",
			wantResources: []string{},
		},
		{
			name:          "minor a menos de 90 dias do EOL",
			server:        &version.Info{Major: "1", Minor: "34", GitVersion: "v1.34.1"},
			now:           time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
			wantStatus:    "warn",
			wantResources: []string{"cluster/v1.34.1"},
		},
		{
			name:          "minor suportada fora da janela de warn",
			server:        &version.Info{Major: "1", Minor: "34", GitVersion: "v1.34.1"},
			now:           base,
			wantStatus:    "pass",
			wantResources: []string{},
		},
		{
			name:          "minor mais nova que a tabela embutida",
			server:        &version.Info{Major: "1", Minor: "99", GitVersion: "v1.99.0"},
			now:           base,
			wantStatus:    "pass",
			wantResources: []string{},
		},
		{
			name:          "major mais nova que a tabela embutida",
			server:        &version.Info{Major: "2", Minor: "0", GitVersion: "v2.0.0"},
			now:           base,
			wantStatus:    "pass",
			wantResources: []string{},
		},
		{
			name:          "minor mais velha que a tabela embutida",
			server:        &version.Info{Major: "1", Minor: "19", GitVersion: "v1.19.0"},
			now:           base,
			wantStatus:    "fail",
			wantResources: []string{"cluster/v1.19.0"},
		},
		{
			name:          "sufixo de provider gerenciado no minor",
			server:        &version.Info{Major: "1", Minor: "33+", GitVersion: "v1.33.9-gke.100"},
			now:           base,
			wantStatus:    "fail",
			wantResources: []string{"cluster/v1.33.9-gke.100"},
		},
		{
			name:          "major e minor vazios caem no GitVersion",
			server:        &version.Info{GitVersion: "v1.33.2"},
			now:           base,
			wantStatus:    "fail",
			wantResources: []string{"cluster/v1.33.2"},
		},
		{
			name:          "versão ilegível por completo",
			server:        &version.Info{GitVersion: "garbage"},
			now:           base,
			wantStatus:    "info",
			wantResources: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := kubernetesVersionSupportCheck{now: func() time.Time { return tc.now }}
			res := c.Run(&snapshot.Snapshot{ServerVersion: tc.server})
			if res.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", res.Status, tc.wantStatus)
			}
			if !reflect.DeepEqual(res.AffectedResources, tc.wantResources) {
				t.Errorf("AffectedResources = %v, want %v", res.AffectedResources, tc.wantResources)
			}
			if !reflect.DeepEqual(res.Namespaces, []string{}) {
				t.Errorf("Namespaces = %v, want non-nil empty (cluster-scoped check)", res.Namespaces)
			}
		})
	}
}

func TestKubernetesVersionSupportCheckID(t *testing.T) {
	if got := (kubernetesVersionSupportCheck{}).ID(); got != "KG-VU-001" {
		t.Errorf("ID() = %q, want KG-VU-001", got)
	}
}

func TestKubernetesVersionSupportCheckZeroValueClock(t *testing.T) {
	// The registry (All) constructs the zero value: a nil now must fall back to time.Now instead
	// of panicking.
	res := kubernetesVersionSupportCheck{}.Run(&snapshot.Snapshot{})
	if res.Status != "info" {
		t.Errorf("Status = %q, want info for a snapshot without ServerVersion", res.Status)
	}
}
