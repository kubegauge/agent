// secrets_test.go table-tests the KG-SE-* checks (secrets.go) against hand-built snapshot fixtures.
package checks

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubegauge/agent/internal/snapshot"
)

// sePod builds an ownerReferences-less Pod with a single container "app" carrying the given
// EnvFrom/Env sources and Volumes, to exercise the KG-SE-002 secret-consumption-pattern check.
func sePod(namespace, name string, envFrom []corev1.EnvFromSource, env []corev1.EnvVar, volumes []corev1.Volume) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", EnvFrom: envFrom, Env: env}},
			Volumes:    volumes,
		},
	}
}

func TestSecretsViaEnvCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "envFrom.secretRef warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{sePod("default", "api",
				[]corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"}}}},
				nil, nil,
			)}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "env[].valueFrom.secretKeyRef warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{sePod("default", "api", nil,
				[]corev1.EnvVar{{Name: "DB_PASSWORD", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"}, Key: "password",
				}}}},
				nil,
			)}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "secret mounted only as a volume passes (this check only looks at env/envFrom)",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{sePod("default", "api", nil, nil,
				[]corev1.Volume{{Name: "creds", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "db-creds"}}}},
			)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "no secret consumption at all passes",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{sePod("default", "api", nil, nil, nil)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "non-secret envFrom/valueFrom (ConfigMap) does not trigger",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{sePod("default", "api",
				[]corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}}}},
				[]corev1.EnvVar{{Name: "LOG_LEVEL", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"}, Key: "log_level",
				}}}},
				nil,
			)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "secret consumed only by an init container still warns",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "default"},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "migrate", EnvFrom: []corev1.EnvFromSource{
						{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "db-creds"}}},
					}}},
					Containers: []corev1.Container{{Name: "app"}},
				},
			}}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"pod/default/api"}},
		},
		{
			name: "kube-system is excluded",
			snap: &snapshot.Snapshot{Pods: []corev1.Pod{sePod("kube-system", "coredns",
				[]corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "x"}}}},
				nil, nil,
			)}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (secretsViaEnvCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestConfigMapCredentialHeuristicCheck(t *testing.T) {
	tests := []struct {
		name string
		snap *snapshot.Snapshot
		want Result
	}{
		{
			name: "key named db_password matches the heuristic and warns",
			snap: &snapshot.Snapshot{ConfigMaps: []snapshot.ConfigMapMeta{
				{Name: "app-config", Namespace: "default", Keys: []string{"db_password", "db_host"}},
			}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"configmap/default/app-config"}},
		},
		{
			name: "innocuous key names pass",
			snap: &snapshot.Snapshot{ConfigMaps: []snapshot.ConfigMapMeta{
				{Name: "app-config", Namespace: "default", Keys: []string{"log_level", "db_host"}},
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
		{
			name: "case-insensitive match: DB_PASSWORD uppercase still warns",
			snap: &snapshot.Snapshot{ConfigMaps: []snapshot.ConfigMapMeta{
				{Name: "app-config", Namespace: "default", Keys: []string{"DB_PASSWORD"}},
			}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"configmap/default/app-config"}},
		},
		{
			name: "api_key and credential variants also match",
			snap: &snapshot.Snapshot{ConfigMaps: []snapshot.ConfigMapMeta{
				{Name: "svc-a", Namespace: "default", Keys: []string{"stripe_api_key"}},
				{Name: "svc-b", Namespace: "default", Keys: []string{"vendor_credential"}},
			}},
			want: Result{Status: "warn", Namespaces: []string{"default"}, AffectedResources: []string{"configmap/default/svc-a", "configmap/default/svc-b"}},
		},
		{
			name: "kube-system is excluded even with a credential-like key",
			snap: &snapshot.Snapshot{ConfigMaps: []snapshot.ConfigMapMeta{
				{Name: "kubeadm-config", Namespace: "kube-system", Keys: []string{"token"}},
			}},
			want: Result{Status: "pass", Namespaces: []string{}, AffectedResources: []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (configMapCredentialHeuristicCheck{}).Run(tt.snap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Run() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
