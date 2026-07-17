// imagevulns.go defines the image-vulnerability enrichment types carried by a Snapshot. They live
// in this package (not internal/trivy) so trivy can import report/snapshot to collect image refs
// without an import cycle: checks read snap.ImageVulns as plain snapshot types and never import
// the scanner.
package snapshot

// ImageCVE is one vulnerability found in an image, already normalized to the contract's lowercase
// severity vocabulary ("critical" | "high" | "medium" | "low").
type ImageCVE struct {
	ID               string
	Severity         string
	Pkg              string
	InstalledVersion string
	FixedVersion     string
	Title            string
}

// ImageScanResult is the per-image outcome: severity counts plus the top CVEs, or a ScanError when
// the image could not be scanned (timeout, private registry auth, parse failure).
type ImageScanResult struct {
	Critical  int
	High      int
	Medium    int
	Low       int
	TopCVEs   []ImageCVE
	ScanError string
}

// ImageVulns is the enrichment attached to a Snapshot after a scanner pass. ByRef is keyed by the
// image reference exactly as it appears in pod specs. A nil *ImageVulns on the Snapshot means the
// scanner was unavailable or disabled (KG-SU-003 reports "info"); a non-nil value with an empty
// map means it ran and found no images to scan.
type ImageVulns struct {
	ByRef map[string]ImageScanResult
}

// systemNamespaces are excluded from workload-oriented checks and from image scanning: their
// contents are managed by the cluster distribution, not the workload team this dashboard is for.
// Moved here from internal/checks (M2) so internal/trivy can share it without importing checks.
var systemNamespaces = map[string]bool{
	"kube-system":        true,
	"kube-public":        true,
	"kube-node-lease":    true,
	"local-path-storage": true,
}

// IsSystemNamespace reports whether ns is managed by the cluster distribution itself.
func IsSystemNamespace(ns string) bool {
	return systemNamespaces[ns]
}
