// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sort"
	"sync"
	"time"
)

const (
	probeEvery   = time.Minute      // /health asks the volumes at most this often
	probeTimeout = 15 * time.Second // per volume
)

// probeAll lists one key of each keyed volume's bucket, at once: the volumes that
// fail (keys not taken, no such bucket, no listing) and why.
func probeAll(ctx context.Context, stores map[string]objectStore) map[string]error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	bad := map[string]error{}
	for name, st := range stores {
		if st.Anonymous() {
			continue // nothing to check without keys
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			if err := st.Probe(pctx); err != nil {
				mu.Lock()
				bad[name] = err
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return bad
}

// probeErr is the first failing volume of probeAll, by name, for -check.
func probeErr(bad map[string]error) error {
	names := make([]string, 0, len(bad))
	for n := range bad {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil
	}
	return fmt.Errorf("volume %q: its bucket cannot be listed with its keys: %v", names[0], bad[names[0]])
}

// volumeHealth keeps the last probe for /health, which never waits for one: a
// stale result starts a new probe in the background. Changes are logged.
type volumeHealth struct {
	mu      sync.Mutex
	at      time.Time
	running bool
	bad     []string
	why     map[string]string // the last error of each failing volume
}

func (s *Server) failingVolumes(now time.Time) []string {
	h := s.health
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running && now.Sub(h.at) >= probeEvery {
		h.running = true
		go func() {
			bad := probeAll(context.Background(), s.stores)
			names, why := make([]string, 0, len(bad)), map[string]string{}
			h.mu.Lock()
			defer h.mu.Unlock()
			for n, err := range bad {
				names, why[n] = append(names, n), err.Error()
				if h.why[n] != why[n] {
					s.errorf("volume_unreachable", n, "volume %q: %v", n, err) // the detail stays in the log
				}
			}
			for n := range h.why {
				if why[n] == "" {
					log.Printf("volume %q: answers again", n)
				}
			}
			sort.Strings(names)
			h.bad, h.why, h.at, h.running = names, why, now, false // when it started
		}()
	}
	return slices.Clone(h.bad)
}
