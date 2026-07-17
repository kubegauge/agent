// cache.go is the trivy result cache: parsed ImageScanResults stored per image key (digest when
// known, ref otherwise) under --trivy-cache-dir, so repeat scans skip the (slow) trivy exec while
// the 24h TTL keeps results fresher than the daily CVE DB updates.
package trivy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
		return snapshot.ImageScanResult{}, false // corrompido = miss, re-escaneia
	}
	if now.Sub(e.StoredAt) > cacheTTL {
		return snapshot.ImageScanResult{}, false
	}
	return e.Result, true
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
