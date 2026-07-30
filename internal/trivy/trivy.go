// trivy.go integrates the local trivy binary into the collector: it scans every unique image in
// use (outside system namespaces) via `trivy image --format json`, caches parsed results on disk
// (cache.go) and fills Snapshot.ImageVulns — the enrichment KG-SU-003 (supplychain.go) reads.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
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
	bin string
	// dbDir is trivy's OWN cache directory (TRIVY_CACHE_DIR), where it keeps the vulnerability
	// database. The agent never writes there; it reads its size for CacheBytes.
	dbDir  string
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
	// The chart points TRIVY_CACHE_DIR at the same volume as cacheDir. Unset (a plain `go run`,
	// where trivy falls back to its own default under the home directory) simply means CacheBytes
	// cannot see the database half.
	return &Scanner{bin: bin, dbDir: os.Getenv("TRIVY_CACHE_DIR"), cache: newDiskCache(cacheDir), runner: defaultRunner, now: time.Now}
}

// CacheBytes reports what the agent's two on-disk caches occupy right now: trivy's own cache
// directory (the vulnerability database, by far the larger) plus the parsed-result cache. In the
// chart both sit on one emptyDir, and exceeding that volume's sizeLimit gets the pod EVICTED with
// the reason recorded only as a kubelet event — invisible to anyone reading `kubectl logs`. Version
// 0.16.0 shipped a limit smaller than the database and every agent with trivy enabled died in an
// eviction loop that looked, from the logs, like a scan that simply stopped. Reporting the number
// every pass puts the growth in the agent's own output, where it can be seen coming.
//
// 0 means nothing was measurable (no TRIVY_CACHE_DIR, result cache disabled, directories not yet
// created or not readable) — never an assertion that the cache is empty.
func (s *Scanner) CacheBytes() int64 {
	total := dirBytes(s.dbDir)
	if s.cache != nil {
		total += dirBytes(s.cache.dir)
	}
	return total
}

// ScanSnapshot scans every unique image used by non-system workloads and returns the enrichment
// for Snapshot.ImageVulns. Always returns non-nil (a nil return is the CALLER's signal for
// "scanner unavailable"). Per-image failures land in ScanError; only successes are cached.
func (s *Scanner) ScanSnapshot(ctx context.Context, snap *snapshot.Snapshot) *snapshot.ImageVulns {
	ctx, cancel := context.WithTimeout(ctx, totalBudget)
	defer cancel()

	// Reclaim the entries whose TTL has passed before writing new ones: the cache lives on an
	// emptyDir, and images come and go.
	s.cache.evictExpired(s.now())

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

	if err := validateImageRef(ref); err != nil {
		return snapshot.ImageScanResult{ScanError: truncate(err.Error(), scanErrorLimit)}
	}

	// "--" ends flag parsing: the reference comes from a pod's image field, which anyone able to
	// create a pod controls, so without it a value like "--server=http://attacker/" would be read
	// by trivy as a flag rather than as an image to scan.
	raw, err := s.runner(ctx, s.bin, "image", "--format", "json", "--quiet", "--", ref)
	if err != nil {
		return snapshot.ImageScanResult{ScanError: truncate(err.Error(), scanErrorLimit)}
	}
	res, err := parseTrivyJSON(raw)
	if err != nil {
		return snapshot.ImageScanResult{ScanError: "trivy JSON parse: " + truncate(err.Error(), scanErrorLimit)}
	}
	return res
}

// imageRefPattern is a conservative superset of the OCI/Docker reference grammar: registry host
// (with an optional port), path components, a tag and/or a digest. It exists to keep hostile input
// out of an exec argument list, not to fully parse references, so it is deliberately stricter than
// the spec — anything it rejects becomes a per-image ScanError the operator can see.
var imageRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)

// maxImageRefLen bounds the argument: no real reference approaches it.
const maxImageRefLen = 512

// validateImageRef rejects an image reference the agent must not hand to a subprocess. Pod specs
// are attacker-controlled input for anyone with pod-create, so a reference that could be read as a
// flag ("-…"), carry shell/whitespace characters, or run to an absurd length never reaches exec —
// on top of the "--" separator scanOne passes.
func validateImageRef(ref string) error {
	switch {
	case ref == "":
		return fmt.Errorf("empty image reference")
	case len(ref) > maxImageRefLen:
		return fmt.Errorf("image reference longer than %d characters, refusing to scan it", maxImageRefLen)
	case !imageRefPattern.MatchString(ref):
		return fmt.Errorf("image reference %q is not a valid reference, refusing to scan it", truncate(ref, 80))
	}
	return nil
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
