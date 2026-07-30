// Package report builds the cluster-truth building blocks of the wire contract (namespaces,
// workloads, network graph, RBAC findings) from a snapshot.Snapshot.
package report

// CveRef mirrors the TS CveRef interface (additive, Trivy integration).
type CveRef struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Pkg              string `json:"pkg"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	Title            string `json:"title,omitempty"`
}

// ImageVulnFinding mirrors the TS ImageVulnFinding interface (additive, Trivy integration).
type ImageVulnFinding struct {
	Image     string   `json:"image"`
	Critical  int      `json:"critical"`
	High      int      `json:"high"`
	Medium    int      `json:"medium"`
	Low       int      `json:"low"`
	TopCves   []CveRef `json:"topCves,omitempty"`
	ScanError string   `json:"scanError,omitempty"`
}

// NetworkNode mirrors the TS NetworkNode interface. Never instantiated by the M1 collector.
type NetworkNode struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
}

// NetworkFlow mirrors the TS NetworkFlow interface. Never instantiated by the M1 collector.
type NetworkFlow struct {
	From     string  `json:"from"`
	To       string  `json:"to"`
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	Verdict  string  `json:"verdict"`
	Policy   *string `json:"policy" jsonschema:"oneof_type=string;null"`
}

// WorkloadPosture mirrors the TS WorkloadPosture interface. Populated (simplified, see workload.go)
// for every Deployment/StatefulSet/DaemonSet and every ownerReferences-less Pod.
type WorkloadPosture struct {
	Name                         string `json:"name"`
	Namespace                    string `json:"namespace"`
	Kind                         string `json:"kind"`
	PsaLevel                     string `json:"psaLevel"`
	RunAsNonRoot                 bool   `json:"runAsNonRoot"`
	ReadOnlyRootFilesystem       bool   `json:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation     bool   `json:"allowPrivilegeEscalation"`
	CapabilitiesDropAll          bool   `json:"capabilitiesDropAll"`
	SeccompProfile               string `json:"seccompProfile"`
	AppArmorProfile              string `json:"appArmorProfile"`
	AutomountServiceAccountToken bool   `json:"automountServiceAccountToken"`
	HostNetwork                  bool   `json:"hostNetwork"`
}

// RbacFinding mirrors the TS RbacFinding interface. Never instantiated by the M1 collector.
type RbacFinding struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	SubjectKind string `json:"subjectKind"`
	Binding     string `json:"binding"`
	BindingKind string `json:"bindingKind"`
	// Namespace is the RoleBinding's own namespace: the boundary its grant stops at, and what the
	// dashboard's namespace filter matches against. Empty for a ClusterRoleBinding, which is
	// cluster-scoped and lives in no namespace at all — filling one in would let a cluster-wide
	// grant disappear behind a namespace filter, which is the opposite of what this field is for.
	//
	// Optional on the wire (omitempty), so an API deployed before this field existed keeps
	// validating reports from agents that send it, and so a report from an older agent stays valid
	// once the API knows it.
	Namespace string `json:"namespace,omitempty"`
	Role      string `json:"role"`
	Risk      string `json:"risk"`
	Reason    string `json:"reason"`
}

// NamespaceInfo mirrors the TS NamespaceInfo interface.
type NamespaceInfo struct {
	Name                  string  `json:"name"`
	PsaEnforce            *string `json:"psaEnforce" jsonschema:"oneof_type=string;null"`
	PsaAudit              *string `json:"psaAudit" jsonschema:"oneof_type=string;null"`
	PsaWarn               *string `json:"psaWarn" jsonschema:"oneof_type=string;null"`
	PodCount              int     `json:"podCount"`
	HasDefaultDenyIngress bool    `json:"hasDefaultDenyIngress"`
	HasDefaultDenyEgress  bool    `json:"hasDefaultDenyEgress"`
}
