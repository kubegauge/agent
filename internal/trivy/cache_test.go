// cache_test.go covers the parsed-result disk cache: roundtrip, TTL expiry, corrupt files and the
// nil (disabled) cache.
package trivy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kubegauge/agent/internal/snapshot"
)

var cacheNow = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

func sampleResult() snapshot.ImageScanResult {
	return snapshot.ImageScanResult{
		High: 2, Medium: 1,
		TopCVEs: []snapshot.ImageCVE{{ID: "CVE-1", Severity: "high", Pkg: "x", InstalledVersion: "1.0"}},
	}
}

func TestDiskCacheRoundtrip(t *testing.T) {
	c := newDiskCache(t.TempDir())
	c.put("sha256:abc", sampleResult(), cacheNow)

	got, ok := c.get("sha256:abc", cacheNow.Add(time.Hour))
	if !ok {
		t.Fatal("esperava cache hit dentro do TTL")
	}
	if !reflect.DeepEqual(got, sampleResult()) {
		t.Errorf("get = %+v, want %+v", got, sampleResult())
	}
}

func TestDiskCacheMissOnDifferentKey(t *testing.T) {
	c := newDiskCache(t.TempDir())
	c.put("sha256:abc", sampleResult(), cacheNow)
	if _, ok := c.get("registry.example.com/team/api:1.4.2", cacheNow); ok {
		t.Error("different keys (digest vs ref) must not collide")
	}
}

func TestDiskCacheExpiresAfterTTL(t *testing.T) {
	c := newDiskCache(t.TempDir())
	c.put("k", sampleResult(), cacheNow)
	if _, ok := c.get("k", cacheNow.Add(cacheTTL+time.Minute)); ok {
		t.Error("expected a miss after the 24h TTL")
	}
}

func TestDiskCacheCorruptFileIsMiss(t *testing.T) {
	dir := t.TempDir()
	c := newDiskCache(dir)
	c.put("k", sampleResult(), cacheNow)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 cache file, got %d (err %v)", len(entries), err)
	}
	if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("{corrompido"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.get("k", cacheNow); ok {
		t.Error("a corrupted file must be treated as a miss")
	}
}

func TestNilDiskCacheIsSafe(t *testing.T) {
	c := newDiskCache("") // dir vazio = cache desabilitado
	if c != nil {
		t.Fatal("newDiskCache(\"\") deve retornar nil")
	}
	c.put("k", sampleResult(), cacheNow) // must not panic
	if _, ok := c.get("k", cacheNow); ok {
		t.Error("a nil cache never hits")
	}
}

// TestDiskCacheEvictsExpiredEntries: the TTL used to be read-side only, so a cache file for an
// image that left the cluster stayed on disk forever — on an emptyDir, that is a slow leak.
func TestDiskCacheEvictsExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	c := newDiskCache(dir)
	c.put("gone", sampleResult(), cacheNow)
	c.put("fresh", sampleResult(), cacheNow.Add(cacheTTL))

	if evicted := c.evictExpired(cacheNow.Add(cacheTTL + time.Minute)); evicted != 1 {
		t.Errorf("evicted %d entries, want 1", evicted)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("cache holds %d files after eviction, want 1", len(entries))
	}
	if _, ok := c.get("fresh", cacheNow.Add(cacheTTL+time.Minute)); !ok {
		t.Error("eviction removed an entry that was still within its TTL")
	}
}

// TestDiskCacheEvictsUnparseableEntries: a corrupt file can never be read again, and only its own
// key would ever overwrite it.
func TestDiskCacheEvictsUnparseableEntries(t *testing.T) {
	dir := t.TempDir()
	c := newDiskCache(dir)
	c.put("k", sampleResult(), cacheNow)
	entries, _ := os.ReadDir(dir)
	if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	if evicted := c.evictExpired(cacheNow); evicted != 1 {
		t.Errorf("evicted %d entries, want the corrupt one gone", evicted)
	}
}

func TestNilDiskCacheEvictionIsSafe(t *testing.T) {
	var c *diskCache
	if got := c.evictExpired(cacheNow); got != 0 {
		t.Errorf("a disabled cache evicted %d entries", got)
	}
}
