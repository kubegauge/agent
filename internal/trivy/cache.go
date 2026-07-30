// cache.go is the trivy result cache: parsed ImageScanResults stored per image key (digest when
// known, ref otherwise) under --trivy-cache-dir, so repeat scans skip the (slow) trivy exec while
// the 24h TTL keeps results fresher than the daily CVE DB updates.
package trivy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubegauge/agent/internal/snapshot"
)

// cacheTTL matches the trivy CVE database's daily update cadence.
const cacheTTL = 24 * time.Hour

// DefaultCacheDir resolves ~/.kubegauge/trivy-cache; "" (cache disabled) if the home dir can't be
// determined — same convention as history.DefaultDir.
func DefaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kubegauge", "trivy-cache")
}

// diskCache stores one JSON file per image key. A nil *diskCache is valid and means "disabled":
// get always misses, put is a no-op.
type diskCache struct {
	dir string
}

func newDiskCache(dir string) *diskCache {
	if dir == "" {
		return nil
	}
	return &diskCache{dir: dir}
}

type cacheEntry struct {
	StoredAt time.Time                `json:"storedAt"`
	Result   snapshot.ImageScanResult `json:"result"`
}

// path hashes the key (an image digest or ref, both full of / and :) into a flat filename.
func (c *diskCache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

func (c *diskCache) get(key string, now time.Time) (snapshot.ImageScanResult, bool) {
	if c == nil {
		return snapshot.ImageScanResult{}, false
	}
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return snapshot.ImageScanResult{}, false
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return snapshot.ImageScanResult{}, false // corrupted = miss, rescan
	}
	if now.Sub(e.StoredAt) > cacheTTL {
		return snapshot.ImageScanResult{}, false
	}
	return e.Result, true
}

// evictExpired deletes entries past the TTL and returns how many went. The TTL used to be
// read-side only: an image that left the cluster left its cache file behind forever, so the
// directory grew without bound on an emptyDir with no size limit. Called once per scan pass, it
// reads one small file per entry — the same files the pass is about to read anyway.
//
// Best-effort throughout: an unreadable directory or a failed unlink must never fail a scan.
func (c *diskCache) evictExpired(now time.Time) int {
	if c == nil {
		return 0
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0
	}
	evicted := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(c.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var e cacheEntry
		// A file that no longer parses is dead weight too: get treats it as a miss and put will
		// never overwrite it unless that exact key comes back.
		if err := json.Unmarshal(data, &e); err == nil && now.Sub(e.StoredAt) <= cacheTTL {
			continue
		}
		if os.Remove(path) == nil {
			evicted++
		}
	}
	return evicted
}

// dirBytes sums the regular files under dir, recursively. Best-effort by design: a missing or
// unreadable directory contributes zero instead of raising an error, because the only consumer is
// an operator-facing log line (Scanner.CacheBytes) that must never be able to fail a scan.
func dirBytes(dir string) int64 {
	if dir == "" {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

// put is best-effort: a cache write failure must never fail a scan. Directories 0700 / files 0600.
func (c *diskCache) put(key string, res snapshot.ImageScanResult, now time.Time) {
	if c == nil {
		return
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return
	}
	data, err := json.Marshal(cacheEntry{StoredAt: now, Result: res})
	if err != nil {
		return
	}
	_ = os.WriteFile(c.path(key), data, 0o600)
}
