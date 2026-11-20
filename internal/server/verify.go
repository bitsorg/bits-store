// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

const (
	verifyTick    = time.Minute      // how often the verifier looks for a bucket due
	verifyRetry   = 10 * time.Minute // after a failed listing, the next try
	verifyTimeout = 6 * time.Hour    // a listing longer than this has stalled
)

// UseIndex gives the running Server, and those of later reloads, the index.
func (r *Reloader) UseIndex(x *index.Index) { r.cur.Load().index = x }

// UseWithdrawals reads the builds withdrawn through the admin API from path (-data's).
func (r *Reloader) UseWithdrawals(path string) error {
	w, err := openWithdrawals(path)
	if err == nil {
		r.cur.Load().withdrawn = w
	}
	return err
}

// UseGC keeps the admin API's collection plans in dir (-data's), made if need be.
func (r *Reloader) UseGC(dir string) error {
	g, err := openGCJobs(dir)
	if err == nil {
		r.cur.Load().gc = g
	}
	return err
}

// Verify lists each keyed bucket against the index, one at a time: when it was
// never verified, then every index_verify; then reads the manifests. It never returns.
func (r *Reloader) Verify() {
	failed := map[string]time.Time{} // bucket -> when its listing failed
	for {
		s := r.cur.Load()
		s.verifyDue(context.Background(), failed)
		s.readManifests(context.Background())
		time.Sleep(verifyTick)
	}
}

// verifyDue verifies the buckets due, by place: two volume names may share a
// bucket, listed once, under the first of their names.
func (s *Server) verifyDue(ctx context.Context, failed map[string]time.Time) {
	names := make([]string, 0, len(s.stores))
	for n, st := range s.stores {
		if !st.Anonymous() {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		bucket := s.place[name]
		if s.now().Sub(failed[bucket]) < verifyRetry {
			continue
		}
		at, _, ok, err := s.index.Verified(ctx, bucket)
		if err != nil {
			s.errorf("index_read_failed", name, "index: volume %q: %v", name, err)
			continue
		}
		if ok && s.now().Sub(at) < s.verifyEvery {
			continue
		}
		start := s.now()
		lctx, cancel := context.WithTimeout(ctx, verifyTimeout)
		d, err := s.index.Verify(lctx, bucket, start, func(add func(index.Object) error) error {
			return s.stores[name].Walk(lctx, func(o index.Object) error {
				if strings.HasPrefix(o.Key, stagingPrefix+"/") {
					return nil // uploads under way: not the store's
				}
				return add(o)
			})
		})
		cancel()
		if err != nil {
			failed[bucket] = s.now()
			s.errorf("listing_failed", name, "index: volume %q not verified, again in %s: %v", name, verifyRetry, err)
			continue
		}
		delete(failed, bucket)
		if _, err := s.index.DropGoneManifests(ctx, bucket); err != nil {
			s.errorf("index_write_failed", name, "index: volume %q: manifests: %v", name, err)
		}
		log.Printf("index: volume %q verified in %s: %d missing, %d changed, %d extra",
			name, s.now().Sub(start).Round(time.Second), d.Missing, d.Changed, d.Extra)
		if ok && d.Missing+d.Changed+d.Extra > 0 { // not a first listing: changed outside the service
			s.record(levelWarning, "index_drift", name, fmt.Sprintf("volume %q: %d objects not written through the service, %d changed, %d gone",
				name, d.Missing, d.Changed, d.Extra))
		}
	}
}
