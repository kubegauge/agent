// helpers_test.go: small builders shared across this package's table-driven tests. No fake
// clientset is needed anywhere in this package's tests — every Check operates on a plain
// *snapshot.Snapshot, so fixtures are built directly as struct literals (same style as
// report/namespace_test.go), never touching a real or fake Kubernetes API.
package checks

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolPtr(b bool) *bool { return &b }

func testNamespace(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}
