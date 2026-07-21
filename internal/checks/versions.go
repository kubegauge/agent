// versions.go implements the KG-VU-* checks (Versions & Upgrades): version-currency posture read
// from snapshot.ServerVersion (the discovery call every snapshot already performs), available on
// every distribution — managed or not — so unlike controlplane.go there is no
// isManagedControlPlane gate here.
//
// KG-VU-001 compares the server's minor release against kubernetesVersionEOL, an embedded table
// of published end-of-life dates (release date + ~14 months of support and maintenance, per the
// upstream release schedule). An embedded table — the same approach tools like kubent take — is
// the only option for a collector that must work without internet access; see the table's doc
// comment for why staleness can only ever err toward pass, never toward a false fail.
package checks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/version"

	"github.com/kubegauge/agent/internal/snapshot"
)

// kubernetesVersionEOL maps each 1.x minor to its published end-of-life date (the end of the
// maintenance period). EOL dates are facts — once announced they don't move — so a stale table
// only affects minors NEWER than its maximum, which Run treats as pass ("newer than this build
// knows about"), never as a false fail. Minors below the table's minimum are years past EOL and
// simply fail.
var kubernetesVersionEOL = map[int]time.Time{
	26: eolDate(2024, time.February, 28),
	27: eolDate(2024, time.June, 28),
	28: eolDate(2024, time.October, 28),
	29: eolDate(2025, time.February, 28),
	30: eolDate(2025, time.June, 28),
	31: eolDate(2025, time.October, 28),
	32: eolDate(2026, time.February, 28),
	33: eolDate(2026, time.June, 28),
	34: eolDate(2026, time.October, 28),
	35: eolDate(2027, time.February, 28),
}

// eolWarnWindow is how close to the EOL date a still-supported minor starts reporting warn:
// 90 days is roughly one Kubernetes release cycle — the last realistic moment to plan the
// minor-by-minor upgrade path before patches stop.
const eolWarnWindow = 90 * 24 * time.Hour

func eolDate(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// kubernetesVersionSupportCheck is KG-VU-001. now is injectable so tests can pin the clock; the
// zero value (what the All registry constructs) falls back to time.Now.
type kubernetesVersionSupportCheck struct {
	now func() time.Time
}

func (kubernetesVersionSupportCheck) ID() string { return "KG-VU-001" }

func (c kubernetesVersionSupportCheck) Run(snap *snapshot.Snapshot) Result {
	unknown := Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}}
	sv := snap.ServerVersion
	if sv == nil {
		return unknown
	}
	major, minor, ok := parseMajorMinor(sv)
	if !ok {
		return unknown
	}

	now := time.Now
	if c.now != nil {
		now = c.now
	}

	// The affected "resource" is the cluster itself; carry the version so the UI shows exactly
	// what was detected (same self-describing spirit as "validatingwebhookconfiguration/<name>").
	gitVersion := sv.GitVersion
	if gitVersion == "" {
		gitVersion = fmt.Sprintf("v%d.%d", major, minor)
	}
	flagged := func(status string) Result {
		return Result{Status: status, Namespaces: []string{}, AffectedResources: []string{"cluster/" + gitVersion}}
	}
	pass := Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}}

	if major != 1 {
		if major > 1 {
			return pass // a future major is newer than anything this table knows
		}
		return flagged("fail") // 0.x predates the table entirely
	}

	maxKnown, minKnown := 0, int(^uint(0)>>1)
	for m := range kubernetesVersionEOL {
		if m > maxKnown {
			maxKnown = m
		}
		if m < minKnown {
			minKnown = m
		}
	}
	switch {
	case minor > maxKnown:
		return pass // released after this build's table — necessarily still supported
	case minor < minKnown:
		return flagged("fail")
	}

	eol := kubernetesVersionEOL[minor]
	switch {
	case !now().Before(eol):
		return flagged("fail")
	case eol.Sub(now()) <= eolWarnWindow:
		return flagged("warn")
	}
	return pass
}

// gitVersionMajorMinor parses "v1.33.2" (or "1.33.2", or GKE's "v1.33.9-gke.100") down to its
// major.minor pair.
var gitVersionMajorMinor = regexp.MustCompile(`^v?(\d+)\.(\d+)`)

// leadingDigits tolerates the "+" suffix managed providers append to version.Info's Minor field
// (e.g. "33+" on GKE).
var leadingDigits = regexp.MustCompile(`^\d+`)

// parseMajorMinor extracts the numeric major/minor pair from a version.Info, preferring the
// dedicated Major/Minor fields and falling back to GitVersion when either is empty or non-numeric.
func parseMajorMinor(sv *version.Info) (int, int, bool) {
	majS := leadingDigits.FindString(strings.TrimSpace(sv.Major))
	minS := leadingDigits.FindString(strings.TrimSpace(sv.Minor))
	if majS != "" && minS != "" {
		maj, _ := strconv.Atoi(majS)
		min, _ := strconv.Atoi(minS)
		return maj, min, true
	}
	if m := gitVersionMajorMinor.FindStringSubmatch(sv.GitVersion); m != nil {
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		return maj, min, true
	}
	return 0, 0, false
}
