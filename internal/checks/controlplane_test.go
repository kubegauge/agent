// controlplane_test.go table-tests the KG-CP-* checks and KG-SE-001 (controlplane.go) against
// hand-built snapshot fixtures — static pods, never a real or fake Kubernetes API, same style as
// every other file in this package.
package checks

import (
	"reflect"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// staticPod builds a kube-system Pod named name, with the given labels, whose single container
// carries command as its full Command (kubeadm's own convention: the entire "binary + flags" argv
// lives in Command, with Args empty).
func staticPod(name string, labels map[string]string, command []string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system", Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: name, Command: command}}},
	}
}

// staticPodWithArgs is the same as staticPod but splits binary into Command and puts the flags in
// Args instead — exercising parseFlags' "flags can live in Args too" tolerance, typically paired
// with the space-separated "--flag value" form.
func staticPodWithArgs(name string, labels map[string]string, binary string, args []string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system", Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: name, Command: []string{binary}, Args: args}}},
	}
}

func apiserverLabels() map[string]string {
	return map[string]string{"component": "kube-apiserver", "tier": "control-plane"}
}

func etcdLabels() map[string]string {
	return map[string]string{"component": "etcd", "tier": "control-plane"}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name    string
		command []string
		args    []string
		want    map[string]string
	}{
		{
			name:    "equals form in Command, binary name skipped",
			command: []string{"kube-apiserver", "--anonymous-auth=false", "--audit-log-path=/var/log/audit.log"},
			want:    map[string]string{"anonymous-auth": "false", "audit-log-path": "/var/log/audit.log"},
		},
		{
			name:    "space-separated form split across Command (binary only) and Args",
			command: []string{"kube-apiserver"},
			args:    []string{"--anonymous-auth", "false", "--audit-log-path", "/var/log/audit.log"},
			want:    map[string]string{"anonymous-auth": "false", "audit-log-path": "/var/log/audit.log"},
		},
		{
			name:    "equals form and space-separated form mixed in the same argv",
			command: []string{"etcd", "--client-cert-auth=true", "--peer-client-cert-auth", "true"},
			want:    map[string]string{"client-cert-auth": "true", "peer-client-cert-auth": "true"},
		},
		{
			name:    "bare boolean flag with no following token defaults to true",
			command: []string{"kube-apiserver", "--profiling"},
			want:    map[string]string{"profiling": "true"},
		},
		{
			name:    "flag immediately followed by another flag has no value, defaults to true",
			command: []string{"kube-apiserver", "--profiling", "--anonymous-auth=false"},
			want:    map[string]string{"profiling": "true", "anonymous-auth": "false"},
		},
		{
			name:    "empty argv yields no flags",
			command: nil,
			args:    nil,
			want:    map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFlags(tt.command, tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseFlags() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestControlPlanePods(t *testing.T) {
	apiserverByName := staticPod("kube-apiserver-node1", nil, []string{"kube-apiserver"})
	apiserverByLabelOnly := staticPod("apiserver-custom-name", apiserverLabels(), []string{"kube-apiserver"})
	etcdPod := staticPod("etcd-node1", nil, []string{"etcd"})
	wrongNamespace := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-node1", Namespace: "default"}}
	unrelated := staticPod("coredns-abc123", nil, []string{"coredns"})

	snap := &snapshot.Snapshot{Pods: []corev1.Pod{apiserverByName, apiserverByLabelOnly, etcdPod, wrongNamespace, unrelated}}

	got := controlPlanePods(snap, apiserverNamePrefix, apiserverComponent)
	names := make([]string, 0, len(got))
	for _, p := range got {
		names = append(names, p.Name)
	}
	sort.Strings(names)

	want := []string{"apiserver-custom-name", "kube-apiserver-node1"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("controlPlanePods(apiserver) names = %v, want %v (wrong-namespace and unrelated pods must be excluded)", names, want)
	}
}

func TestIsManagedControlPlane(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want bool
	}{
		{
			name: "eks-style node providerID with no static pods is managed",
			snap: &snapshot.Snapshot{Nodes: []corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0123456789"}}}},
			want: true,
		},
		{
			name: "eks distribution is managed even if a pod named like an apiserver static pod exists",
			snap: &snapshot.Snapshot{
				Nodes: []corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0123456789"}}},
				Pods:  []corev1.Pod{staticPod("kube-apiserver-node1", nil, []string{"kube-apiserver"})},
			},
			want: true,
		},
		{
			name: "no nodes, no static pods, unknown distribution: nothing to introspect, so managed",
			snap: &snapshot.Snapshot{},
			want: true,
		},
		{
			name: "unknown distribution WITH an apiserver static pod present is NOT managed",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", nil, []string{"kube-apiserver"})}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isManagedControlPlane(tt.snap); got != tt.want {
				t.Errorf("isManagedControlPlane() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApiserverAnonymousAuthCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "anonymous-auth=false (equals form) passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "anonymous-auth false via space-separated Args passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPodWithArgs("kube-apiserver-node1", apiserverLabels(), "kube-apiserver", []string{"--anonymous-auth", "false"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "anonymous-auth=true fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=true"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "flag entirely absent fails (Kubernetes' own default is true)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--audit-log-path=/var/log/audit.log"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "HA control plane: one compliant node and one not — only the offender is listed",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"}),
				staticPod("kube-apiserver-node2", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=true"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node2"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (apiserverAnonymousAuthCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAuditLogPathCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "audit-log-path set (equals form) passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--audit-log-path=/var/log/kubernetes/audit.log"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "audit-log-path set via separate Args (space form) passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPodWithArgs("kube-apiserver-node1", apiserverLabels(), "kube-apiserver", []string{"--audit-log-path", "/var/log/kubernetes/audit.log"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "audit-log-path missing fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (auditLogPathCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEtcdClientCertAuthCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "both client and peer cert auth true passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"}),
				staticPod("etcd-node1", etcdLabels(), []string{"etcd", "--client-cert-auth=true", "--peer-client-cert-auth=true"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "peer-client-cert-auth missing fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver"}),
				staticPod("etcd-node1", etcdLabels(), []string{"etcd", "--client-cert-auth=true"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/etcd-node1"}},
		},
		{
			name: "both flags explicitly false fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver"}),
				staticPod("etcd-node1", etcdLabels(), []string{"etcd", "--client-cert-auth=false", "--peer-client-cert-auth=false"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/etcd-node1"}},
		},
		{
			name: "apiserver present but etcd static pod absent (e.g. external etcd) is info, not a false pass",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver"}),
			}},
			want: Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (etcdClientCertAuthCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNodeRestrictionAdmissionCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "NodeRestriction present among several plugins passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--enable-admission-plugins=NodeRestriction,PodSecurity"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "enable-admission-plugins set without NodeRestriction fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--enable-admission-plugins=PodSecurity"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "flag entirely absent fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (nodeRestrictionAdmissionCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAlwaysPullImagesAdmissionCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "AlwaysPullImages present among several plugins passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--enable-admission-plugins=NodeRestriction,AlwaysPullImages"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "enable-admission-plugins set without AlwaysPullImages warns (not fail: hardening debatido, ver catálogo)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--enable-admission-plugins=NodeRestriction"})}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "flag entirely absent warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver"})}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "substring of another plugin name does not false-match (AlwaysPullImagesExtra)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--enable-admission-plugins=AlwaysPullImagesExtra"})}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (alwaysPullImagesAdmissionCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPodSecurityAdmissionNotDisabledCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "disable-admission-plugins entirely absent passes (PodSecurity é default desde 1.25)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "disable-admission-plugins set without PodSecurity passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--disable-admission-plugins=AlwaysAdmit"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "PodSecurity explicitly disabled fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--disable-admission-plugins=PodSecurity,AlwaysAdmit"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (podSecurityNotDisabledCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAuditPolicyAndRetentionCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "policy file and all three retention flags set passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{
				"kube-apiserver",
				"--audit-policy-file=/etc/kubernetes/audit-policy.yaml",
				"--audit-log-maxage=30", "--audit-log-maxbackup=10", "--audit-log-maxsize=100",
			})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "same flags via space-separated Args passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPodWithArgs("kube-apiserver-node1", apiserverLabels(), "kube-apiserver", []string{
				"--audit-policy-file", "/etc/kubernetes/audit-policy.yaml",
				"--audit-log-maxage", "30", "--audit-log-maxbackup", "10", "--audit-log-maxsize", "100",
			})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "policy file set but retention flags missing fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{
				"kube-apiserver", "--audit-policy-file=/etc/kubernetes/audit-policy.yaml",
			})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "retention flags set but policy file missing fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{
				"kube-apiserver", "--audit-log-maxage=30", "--audit-log-maxbackup=10", "--audit-log-maxsize=100",
			})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "no audit flags at all fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (auditPolicyAndRetentionCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationModeCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "Node,RBAC passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--authorization-mode=Node,RBAC"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "Node,RBAC,Webhook via space-separated Args passes (extra modes are fine)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPodWithArgs("kube-apiserver-node1", apiserverLabels(), "kube-apiserver", []string{"--authorization-mode", "Node,RBAC,Webhook"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "flag entirely absent fails (Kubernetes' own default is AlwaysAllow)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "AlwaysAllow alone fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--authorization-mode=AlwaysAllow"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "Node,RBAC with AlwaysAllow appended still fails (AlwaysAllow short-circuits every request)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--authorization-mode=Node,RBAC,AlwaysAllow"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "RBAC without Node fails (CIS 1.2.7 requires Node too)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--authorization-mode=RBAC"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (authorizationModeCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestProfilingDisabledCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "all three components with profiling=false passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--profiling=false"}),
				staticPod("kube-scheduler-node1", nil, []string{"kube-scheduler", "--profiling=false"}),
				staticPod("kube-controller-manager-node1", nil, []string{"kube-controller-manager", "--profiling=false"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "apiserver alone with profiling=false passes (absent scheduler/controller-manager pods are simply not evaluated)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--profiling=false"}),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "scheduler without the flag fails listing only the scheduler (default is profiling enabled)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--profiling=false"}),
				staticPod("kube-scheduler-node1", nil, []string{"kube-scheduler"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-scheduler-node1"}},
		},
		{
			name: "apiserver with explicit profiling=true fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--profiling=true"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
		{
			name: "flag absent on all three components fails listing all three",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{
				staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver"}),
				staticPod("kube-scheduler-node1", nil, []string{"kube-scheduler"}),
				staticPod("kube-controller-manager-node1", nil, []string{"kube-controller-manager"}),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{
				"pod/kube-system/kube-apiserver-node1",
				"pod/kube-system/kube-controller-manager-node1",
				"pod/kube-system/kube-scheduler-node1",
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (profilingDisabledCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestOidcAuthenticationCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "oidc-issuer-url set passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--oidc-issuer-url=https://idp.example.com"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "oidc-issuer-url via space-separated Args passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPodWithArgs("kube-apiserver-node1", apiserverLabels(), "kube-apiserver", []string{"--oidc-issuer-url", "https://idp.example.com"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "structured authentication config (K8s 1.30+) passes as the OIDC flags' successor",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--authentication-config=/etc/kubernetes/authn-config.yaml"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "neither flag present warns (not fail: cert-based authn não é insegura em si)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"})}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (oidcAuthenticationCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEncryptionAtRestCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "encryption-provider-config set passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--encryption-provider-config=/etc/kubernetes/enc/enc.yaml"})}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "encryption-provider-config absent fails (secrets stored as base64, not encrypted, in etcd)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{staticPod("kube-apiserver-node1", apiserverLabels(), []string{"kube-apiserver", "--anonymous-auth=false"})}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{"pod/kube-system/kube-apiserver-node1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (encryptionAtRestCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestManagedControlPlaneDegradesEveryCheckToInfo is the dedicated test for this milestone's
// "cluster managed (sem static pods) -> tudo info" requirement: every KG-CP-*/KG-SE-001 check
// implemented in controlplane.go, run against either an EKS-shaped snapshot or a bare snapshot
// with no control-plane static pods at all, must report info with empty resources — never a guess.
func TestManagedControlPlaneDegradesEveryCheckToInfo(t *testing.T) {
	wantInfo := Result{Status: "info", Namespaces: []string{}, AffectedResources: []string{}}

	controlPlaneChecks := []Check{
		apiserverAnonymousAuthCheck{},
		auditLogPathCheck{},
		etcdClientCertAuthCheck{},
		nodeRestrictionAdmissionCheck{},
		alwaysPullImagesAdmissionCheck{},
		podSecurityNotDisabledCheck{},
		auditPolicyAndRetentionCheck{},
		authorizationModeCheck{},
		profilingDisabledCheck{},
		oidcAuthenticationCheck{},
		encryptionAtRestCheck{},
	}

	snaps := map[string]*snapshot.Snapshot{
		"eks distribution, no static pods at all": {
			Nodes: []corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0123456789"}}},
		},
		"unknown distribution and no apiserver static pod (nothing to introspect)": {},
	}

	for snapName, snap := range snaps {
		for _, c := range controlPlaneChecks {
			t.Run(snapName+"/"+c.ID(), func(t *testing.T) {
				got := c.Run(snap)
				if !reflect.DeepEqual(got, wantInfo) {
					t.Errorf("Run() = %+v, want %+v", got, wantInfo)
				}
			})
		}
	}
}
