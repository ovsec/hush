package p2p

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	ma "github.com/multiformats/go-multiaddr"
)

// book remembers, per member, where they were last reachable and when they
// were last seen online. It holds addresses and times only, never secrets.
type book struct {
	path string

	mu      sync.Mutex
	entries map[string]*bookEntry
	dirty   bool
}

type bookEntry struct {
	Addrs    []string `json:"addrs"`
	LastSeen int64    `json:"last_seen"`
}

const maxAddrs = 16

func loadBook(path string) *book {
	b := &book{path: path, entries: map[string]*bookEntry{}}
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &b.entries)
	}
	return b
}

func (b *book) entry(id string) *bookEntry {
	e, ok := b.entries[id]
	if !ok {
		e = &bookEntry{}
		b.entries[id] = e
	}
	return e
}

func (b *book) seen(id string, t time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.entry(id); t.UnixMilli() > e.LastSeen {
		e.LastSeen = t.UnixMilli()
		b.dirty = true
	}
}

func (b *book) lastSeen(id string) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.entries[id]; ok && e.LastSeen > 0 {
		return time.UnixMilli(e.LastSeen)
	}
	return time.Time{}
}

func (b *book) setAddrs(id string, addrs []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entry(id)
	seen := map[string]bool{}
	var merged []string
	for _, a := range append(append([]string{}, addrs...), e.Addrs...) {
		if !seen[a] && len(merged) < maxAddrs {
			seen[a] = true
			merged = append(merged, a)
		}
	}
	e.Addrs = merged
	b.dirty = true
}

func (b *book) addrs(id string) []ma.Multiaddr {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []ma.Multiaddr
	if e, ok := b.entries[id]; ok {
		for _, a := range e.Addrs {
			if m, err := ma.NewMultiaddr(a); err == nil {
				out = append(out, m)
			}
		}
	}
	return out
}

func (b *book) save() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.dirty {
		return
	}
	data, err := json.MarshalIndent(b.entries, "", "  ")
	if err != nil {
		return
	}
	tmp := b.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil && os.Rename(tmp, b.path) == nil {
		b.dirty = false
	}
}
