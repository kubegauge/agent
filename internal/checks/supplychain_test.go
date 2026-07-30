// supplychain_test.go table-tests the KG-SU-* checks (supplychain.go) against hand-built snapshot fixtures.
package checks

import (
	"reflect"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// suPod builds an ownerReferences-less Pod with a single container "app" using the given image,
// to exercise the KG-SU-* image supply-chain checks.
func suPod(namespace, name, image string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
	}
}

func TestMutableImageTagCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "image without any tag (implicit latest) fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("default", "api", "nginx")}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "image with explicit :latest tag fails",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("default", "api", "nginx:latest")}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "image pinned by digest passes even without a tag",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("default", "api", "nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "image with an explicit non-latest tag passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("default", "api", "nginx:1.25")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "init container with a mutable tag fails even when the main container is pinned",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "migrate", Image: "migrate:latest"}},
					Containers:     []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				},
			}}},
			want: Result{Status: "fail", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("kube-system", "coredns", "coredns")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (mutableImageTagCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRegistryAllowlistCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "registry outside the allowlist warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("default", "api", "registry.example.com/app:1.0")}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "implicit docker.io image (no registry segment) passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("default", "api", "bitnami/postgres:14")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "explicit allowlisted registry (gcr.io) passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("default", "api", "gcr.io/my-project/app:1.0")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "init container pulling from a disallowed registry warns even if the main container is fine",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "migrate", Image: "internal.example.com/migrate:1.0"}},
					Containers:     []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
				},
			}}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "kube-system is excluded even with a disallowed registry",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{suPod("kube-system", "custom-agent", "registry.example.com/agent:1.0")}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (registryAllowlistCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func vulnSnapshot(vulns *snapshot.ImageVulns, deps ...appsv1.Deployment) *snapshot.Snapshot {
	return &snapshot.Snapshot{Deployments: deps, ImageVulns: vulns}
}

func imageDeployment(ns, name, image string) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: image}},
		}}},
	}
}

func TestImageVulnScanCheck(t *testing.T) {
	check := imageVulnScanCheck{}

	t.Run("no scanner becomes info", func(t *testing.T) {
		res := check.Run(&snapshot.Snapshot{})
		if res.Status != "info" || len(res.AffectedResources) != 0 || res.ImageFindings != nil {
			t.Errorf("Run = %+v, want info with no resources and no findings", res)
		}
	})

	t.Run("critical vira fail com workload afetado", func(t *testing.T) {
		snap := vulnSnapshot(
			&snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{
				"api:1.0": {Critical: 2, High: 1},
			}},
			imageDeployment("default", "api", "api:1.0"),
		)
		res := check.Run(snap)
		if res.Status != "fail" {
			t.Errorf("Status = %s, want fail", res.Status)
		}
		if !reflect.DeepEqual(res.AffectedResources, []string{"deploy/default/api"}) {
			t.Errorf("AffectedResources = %v, want [deploy/default/api]", res.AffectedResources)
		}
		if !reflect.DeepEqual(res.Namespaces, []string{"default"}) {
			t.Errorf("Namespaces = %v, want [default]", res.Namespaces)
		}
		if len(res.ImageFindings) != 1 || res.ImageFindings[0].Image != "api:1.0" || res.ImageFindings[0].Critical != 2 {
			t.Errorf("ImageFindings = %+v, want api:1.0 com Critical=2", res.ImageFindings)
		}
	})

	t.Run("high alone becomes warn", func(t *testing.T) {
		snap := vulnSnapshot(
			&snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{"api:1.0": {High: 3}}},
			imageDeployment("default", "api", "api:1.0"),
		)
		if res := check.Run(snap); res.Status != "warn" {
			t.Errorf("Status = %s, want warn", res.Status)
		}
	})

	t.Run("neither high nor critical becomes pass, with findings", func(t *testing.T) {
		snap := vulnSnapshot(
			&snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{"api:1.0": {Medium: 5, Low: 2}}},
			imageDeployment("default", "api", "api:1.0"),
		)
		res := check.Run(snap)
		if res.Status != "pass" || len(res.AffectedResources) != 0 {
			t.Errorf("Run = %+v, want pass with no affected resources", res)
		}
		if len(res.ImageFindings) != 1 || res.ImageFindings[0].Medium != 5 {
			t.Errorf("findings must be present even on a pass: %+v", res.ImageFindings)
		}
	})

	t.Run("every image failing becomes warn", func(t *testing.T) {
		snap := vulnSnapshot(
			&snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{
				"a:1": {ScanError: "timeout"}, "b:2": {ScanError: "auth"},
			}},
			imageDeployment("default", "a", "a:1"), imageDeployment("default", "b", "b:2"),
		)
		res := check.Run(snap)
		if res.Status != "warn" || len(res.AffectedResources) != 0 {
			t.Errorf("Run = %+v, want warn with no resources (nothing was scanned)", res)
		}
		if res.ImageFindings[0].ScanError == "" {
			t.Errorf("the finding must carry the ScanError: %+v", res.ImageFindings[0])
		}
	})

	t.Run("scanner ran but the cluster has no workloads: pass", func(t *testing.T) {
		snap := vulnSnapshot(&snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{}})
		if res := check.Run(snap); res.Status != "pass" {
			t.Errorf("Status = %s, want pass", res.Status)
		}
	})

	t.Run("findings ordenadas por ref e CVEs convertidas", func(t *testing.T) {
		snap := vulnSnapshot(
			&snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{
				"zeta:1": {High: 1},
				"alfa:1": {High: 1, TopCVEs: []snapshot.ImageCVE{{ID: "CVE-9", Severity: "high", Pkg: "p", InstalledVersion: "1", FixedVersion: "2", Title: "t"}}},
			}},
			imageDeployment("default", "z", "zeta:1"), imageDeployment("default", "a", "alfa:1"),
		)
		res := check.Run(snap)
		if res.ImageFindings[0].Image != "alfa:1" || res.ImageFindings[1].Image != "zeta:1" {
			t.Errorf("findings out of order: %+v", res.ImageFindings)
		}
		cve := res.ImageFindings[0].TopCves[0]
		if cve.ID != "CVE-9" || cve.Severity != "high" || cve.FixedVersion != "2" {
			t.Errorf("incorrect ImageCVE→CveRef conversion: %+v", cve)
		}
	})
}

func TestRunCarriesImageFindingsIntoComplianceCheck(t *testing.T) {
	snap := vulnSnapshot(
		&snapshot.ImageVulns{ByRef: map[string]snapshot.ImageScanResult{"api:1.0": {Critical: 1}}},
		imageDeployment("default", "api", "api:1.0"),
	)
	for _, c := range Run(snap) {
		if c.ID == "KG-SU-003" {
			if len(c.ImageFindings) != 1 {
				t.Errorf("Run must copy ImageFindings into the ComplianceCheck: %+v", c.ImageFindings)
			}
			return
		}
	}
	t.Fatal("KG-SU-003 missing from Run output — check not registered in All?")
}

// signatureWebhookCfg builds a ValidatingWebhookConfiguration fixture for the KG-SU-004 tests:
// cfgName as metadata.name plus one admission webhook entry per webhookNames.
func signatureWebhookCfg(cfgName string, webhookNames ...string) admissionregistrationv1.ValidatingWebhookConfiguration {
	cfg := admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: cfgName},
	}
	for _, n := range webhookNames {
		cfg.Webhooks = append(cfg.Webhooks, admissionregistrationv1.ValidatingWebhook{Name: n})
	}
	return cfg
}

func TestImageSignatureVerificationCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "sigstore policy-controller webhook presente passa",
			snap: &snapshot.Snapshot{ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{
				signatureWebhookCfg("policy.sigstore.dev", "policy.sigstore.dev"),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "connaisseur webhook presente passa",
			snap: &snapshot.Snapshot{ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{
				signatureWebhookCfg("connaisseur-webhook", "connaisseur-svc.connaisseur.svc"),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "match via webhook entry name, not just the config (config with a custom name)",
			snap: &snapshot.Snapshot{ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{
				signatureWebhookCfg("image-policy", "enforcer.policy.sigstore.dev"),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "kyverno alone becomes warn listing the configs (verifyImages not confirmable via webhook)",
			snap: &snapshot.Snapshot{ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{
				signatureWebhookCfg("kyverno-resource-validating-webhook-cfg", "validate.kyverno.svc-fail"),
				signatureWebhookCfg("kyverno-policy-validating-webhook-cfg", "validate-policy.kyverno.svc"),
			}},
			want: Result{Status: "warn", Namespaces: []string{}, AffectedResources: []string{
				"validatingwebhookconfiguration/kyverno-policy-validating-webhook-cfg",
				"validatingwebhookconfiguration/kyverno-resource-validating-webhook-cfg",
			}},
		},
		{
			name: "kyverno E policy-controller juntos: o verificador dedicado ganha, passa",
			snap: &snapshot.Snapshot{ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{
				signatureWebhookCfg("kyverno-resource-validating-webhook-cfg", "validate.kyverno.svc-fail"),
				signatureWebhookCfg("policy.sigstore.dev", "policy.sigstore.dev"),
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "no webhook config in the cluster fails",
			snap: &snapshot.Snapshot{},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "only unrelated webhooks (cert-manager) fails",
			snap: &snapshot.Snapshot{ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{
				signatureWebhookCfg("cert-manager-webhook", "webhook.cert-manager.io"),
			}},
			want: Result{Status: "fail", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (imageSignatureVerificationCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
