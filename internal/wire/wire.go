// Package wire defines the AgentReport v1 push contract (agent → KubeGauge API) and assembles it
// from a snapshot. This is the ONLY payload that ever leaves the cluster; schema/agent-report.v1.schema.json
// is generated from these structs (cmd/genschema) and docs/what-leaves-your-cluster.md documents it.
package wire

import (
	"time"

	"github.com/kubegauge/agent/internal/report"
	"github.com/kubegauge/agent/internal/snapshot"
)

// SchemaVersion is the current wire contract version. The API accepts N and N-1; every change
// within a version is strictly additive.
const SchemaVersion = 1

// AgentReport is the complete push payload: everything that requires cluster access, and nothing
// else — no educational/editorial content (explanation, remediation, framework refs) ever travels;
// the backend joins that by check id.
type AgentReport struct {
	SchemaVersion int            `json:"schemaVersion"`
	AgentVersion  string         `json:"agentVersion"`
	ClusterName   string         `json:"clusterName"`
	TakenAt       string         `json:"takenAt"` // RFC3339, UTC
	Kubernetes    KubernetesInfo `json:"kubernetes"`
	// Checks carries the raw runtime verdict per check id (the "evidence"): status plus the
	// namespaces/resources it was computed from. Nothing here is human-authored text.
	Checks       []CheckResult            `json:"checks"`
	Namespaces   []report.NamespaceInfo   `json:"namespaces"`
	Workloads    []report.WorkloadPosture `json:"workloads"`
	RbacFindings []report.RbacFinding     `json:"rbacFindings"`
	Network      Network                  `json:"network"`
}

// KubernetesInfo summarizes the cluster: version/distribution/counts (spec §4).
type KubernetesInfo struct {
	Version        string `json:"version"`
	Distribution   string `json:"distribution"`
	NodeCount      int    `json:"nodeCount"`
	NamespaceCount int    `json:"namespaceCount"`
}

// CheckResult is one check's raw outcome. ImageFindings only appears on scanner-fed checks
// (KG-SU-003) — same omitempty semantics the old joined contract had.
type CheckResult struct {
	ID                string                    `json:"id"`
	Status            string                    `json:"status"`
	Namespaces        []string                  `json:"namespaces"`
	AffectedResources []string                  `json:"affectedResources"`
	ImageFindings     []report.ImageVulnFinding `json:"imageFindings,omitempty"`
}

// Network carries the NetworkPolicy evaluation graph (BuildNetwork output — Kubernetes semantics,
// not editorial content).
type Network struct {
	Nodes []report.NetworkNode `json:"nodes"`
	Flows []report.NetworkFlow `json:"flows"`
}

// Build assembles the full AgentReport from a snapshot plus the pre-computed raw check results and
// RBAC findings (computed by internal/checks — importing it here would cycle). Pure function; every
// slice is normalized non-nil so the payload never carries a null array.
func Build(snap *snapshot.Snapshot, clusterName, agentVersion string, takenAt time.Time, checks []CheckResult, rbacFindings []report.RbacFinding) *AgentReport {
	gitVersion := ""
	if snap.ServerVersion != nil {
		gitVersion = snap.ServerVersion.GitVersion
	}
	nodes, flows := report.BuildNetwork(snap)
	namespaces := report.BuildNamespaces(snap)
	if checks == nil {
		checks = []CheckResult{}
	}
	if rbacFindings == nil {
		rbacFindings = []report.RbacFinding{}
	}
	return &AgentReport{
		SchemaVersion: SchemaVersion,
		AgentVersion:  agentVersion,
		ClusterName:   clusterName,
		TakenAt:       takenAt.UTC().Format(time.RFC3339),
		Kubernetes: KubernetesInfo{
			Version:        gitVersion,
			Distribution:   report.DetectDistribution(snap.Nodes, gitVersion, snap.KubeadmConfigMapFound),
			NodeCount:      len(snap.Nodes),
			NamespaceCount: len(namespaces),
		},
		Checks:       checks,
		Namespaces:   namespaces,
		Workloads:    report.BuildWorkloads(snap),
		RbacFindings: rbacFindings,
		Network:      Network{Nodes: nodes, Flows: flows},
	}
}
