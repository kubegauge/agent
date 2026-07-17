// trivy.go integrates the local trivy binary into the collector: it scans every unique image in
// use (outside system namespaces) via `trivy image --format json`, caches parsed results on disk
// (cache.go) and fills Snapshot.ImageVulns — the enrichment KG-SU-003 (supplychain.go) reads.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// topCVELimit bounds TopCVEs per image: enough to be didactic in the drawer without bloating the
// report (a busy image easily has hundreds of CVEs).
const topCVELimit = 5

// trivyReport maps only the stable subset of `trivy image --format json` (schema v2) we consume.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

// severityFromTrivy normalizes trivy's uppercase severities to the contract vocabulary; anything
// absent here (UNKNOWN) is dropped — no severity signal, no actionable value.
var severityFromTrivy = map[string]string{
	"CRITICAL": "critical",
	"HIGH":     "high",
	"MEDIUM":   "medium",
	"LOW":      "low",
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// parseTrivyJSON turns raw `trivy image --format json` output into an ImageScanResult: severity
// counts over every result section, plus the topCVELimit worst CVEs (severity, then id, for
// deterministic output).
func parseTrivyJSON(data []byte) (snapshot.ImageScanResult, error) {
	var rpt trivyReport
	if err := json.Unmarshal(data, &rpt); err != nil {
		return snapshot.ImageScanResult{}, err
	}

	var res snapshot.ImageScanResult
	var all []snapshot.ImageCVE
	for _, r := range rpt.Results {
		for _, v := range r.Vulnerabilities {
			sev, ok := severityFromTrivy[v.Severity]
			if !ok {
				continue
			}
			switch sev {
			case "critical":
				res.Critical++
			case "high":
				res.High++
			case "medium":
				res.Medium++
			case "low":
				res.Low++
			}
			all = append(all, snapshot.ImageCVE{
				ID: v.VulnerabilityID, Severity: sev, Pkg: v.PkgName,
				InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion, Title: v.Title,
			})
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if severityRank[all[i].Severity] != severityRank[all[j].Severity] {
			return severityRank[all[i].Severity] < severityRank[all[j].Severity]
		}
		return all[i].ID < all[j].ID
	})
	if len(all) > topCVELimit {
		all = all[:topCVELimit]
	}
	res.TopCVEs = all
	return res, nil
}

const (
	// totalBudget bounds one whole enrichment pass; perImageBudget bounds each trivy exec. Both
	// are constants in v1 (no flags) — see SPEC-TRIVY-KG-SU-003.md §1.
	totalBudget    = 5 * time.Minute
	perImageBudget = 90 * time.Second
	// scanErrorLimit truncates stderr noise carried into per-image ScanError messages.
	scanErrorLimit = 200
)

// runnerFunc executes the trivy binary; injectable so tests never exec anything real.
type runnerFunc func(ctx context.Context, bin string, args ...string) ([]byte, error)

// Scanner wraps the local trivy binary. Construct via NewScanner; a nil *Scanner means "trivy
// unavailable" and callers must then leave Snapshot.ImageVulns nil (KG-SU-003 reports info).
type Scanner struct {
	bin    string
	cache  *diskCache
	runner runnerFunc
	now    func() time.Time
}

// NewScanner discovers trivy on PATH; nil when absent (graceful degradation, never an error).
// cacheDir "" disables the parsed-result cache but not the scan itself.
func NewScanner(cacheDir string) *Scanner {
	bin, err := exec.LookPath("trivy")
	if err != nil {
		return nil
	}
	return &Scanner{bin: bin, cache: newDiskCache(cacheDir), runner: defaultRunner, now: time.Now}
}

// ScanSnapshot scans every unique image used by non-system workloads and returns the enrichment
// for Snapshot.ImageVulns. Always returns non-nil (a nil return is the CALLER's signal for
// "scanner unavailable"). Per-image failures land in ScanError; only successes are cached.
func (s *Scanner) ScanSnapshot(ctx context.Context, snap *snapshot.Snapshot) *snapshot.ImageVulns {
	ctx, cancel := context.WithTimeout(ctx, totalBudget)
	defer cancel()

	digests := imageDigests(snap)
	out := &snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{}}
	for _, ref := range collectImageRefs(snap) {
		key := ref
		if d := digests[ref]; d != "" {
			key = d
		}
		if res, ok := s.cache.get(key, s.now()); ok {
			out.ByRef[ref] = res
			continue
		}
		res := s.scanOne(ctx, ref)
		if res.ScanError == "" {
			s.cache.put(key, res, s.now())
		}
		out.ByRef[ref] = res
	}
	return out
}

func (s *Scanner) scanOne(ctx context.Context, ref string) snapshot.ImageScanResult {
	ctx, cancel := context.WithTimeout(ctx, perImageBudget)
	defer cancel()

	raw, err := s.runner(ctx, s.bin, "image", "--format", "json", "--quiet", ref)
	if err != nil {
		return snapshot.ImageScanResult{ScanError: truncate(err.Error(), scanErrorLimit)}
	}
	res, err := parseTrivyJSON(raw)
	if err != nil {
		return snapshot.ImageScanResult{ScanError: "parse do JSON do trivy: " + truncate(err.Error(), scanErrorLimit)}
	}
	return res
}

// collectImageRefs gathers every container and initContainer image of non-system workloads,
// deduplicated and sorted — the same population KG-SU-001/002 audit.
func collectImageRefs(snap *snapshot.Snapshot) []string {
	set := map[string]bool{}
	for _, src := range report.WorkloadSources(snap) {
		if snapshot.IsSystemNamespace(src.Namespace) {
			continue
		}
		for _, c := range src.Spec.Containers {
			if c.Image != "" {
				set[c.Image] = true
			}
		}
		for _, c := range src.Spec.InitContainers {
			if c.Image != "" {
				set[c.Image] = true
			}
		}
	}
	refs := make([]string, 0, len(set))
	for ref := range set {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

// imageDigests maps image refs to the digest live pods report for them (ContainerStatus.ImageID,
// "repo@sha256:..."). Preferred as cache key: immutable even when a mutable tag is repushed.
func imageDigests(snap *snapshot.Snapshot) map[string]string {
	out := map[string]string{}
	for _, p := range snap.Pods {
		statuses := make([]corev1.ContainerStatus, 0, len(p.Status.ContainerStatuses)+len(p.Status.InitContainerStatuses))
		statuses = append(statuses, p.Status.ContainerStatuses...)
		statuses = append(statuses, p.Status.InitContainerStatuses...)
		for _, st := range statuses {
			if at := strings.Index(st.ImageID, "@"); at != -1 && st.Image != "" {
				out[st.Image] = st.ImageID[at+1:]
			}
		}
	}
	return out
}

func defaultRunner(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%v: %s", err, msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
