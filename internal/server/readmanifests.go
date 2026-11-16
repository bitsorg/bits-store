// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

const manifestTimeout = 2 * time.Minute

var (
	manifestsPerTick       = 500      // files read a tick, per bucket: a first fill takes several
	maxManifest      int64 = 16 << 20 // a bigger file is no manifest (an SBOM, say): not read
)

// readManifests indexes what the files under each bucket's manifests bindings say:
// the new and changed ones, never on a request. One that cannot be read (or is gone)
// is noted as unread and tried again after index.RetryUnread.
func (s *Server) readManifests(ctx context.Context) {
	prefixes, keyed := map[string][]string{}, map[string]string{} // bucket -> prefixes; its first volume
	for _, b := range s.bindings {
		at, p := s.place[b.Volume], strings.TrimSuffix(b.KeyPrefix, "/")
		if b.Format != "manifests" || s.stores[b.Volume].Anonymous() {
			continue
		}
		if n, ok := keyed[at]; !ok || b.Volume < n {
			keyed[at] = b.Volume
		}
		if !slices.Contains(prefixes[at], p) {
			prefixes[at] = append(prefixes[at], p)
		}
	}
	for _, bucket := range slices.Sorted(maps.Keys(prefixes)) {
		name := keyed[bucket]
		counts, err := s.readBucketManifests(ctx, bucket, name, prefixes[bucket])
		if counts[index.KindBOM]+counts[index.KindCommon]+counts[index.KindNone] > 0 {
			log.Printf("index: volume %q: manifests read: %d BOMs, %d common, %d others",
				name, counts[index.KindBOM], counts[index.KindCommon], counts[index.KindNone])
		}
		if err != nil {
			log.Printf("index: volume %q: manifests not read, again in %s: %v", name, index.RetryUnread, err)
		}
	}
}

// readBucketManifests reads up to manifestsPerTick files of a bucket, by kind; at
// the first that cannot be read (noted as unread) the bucket waits for the next tick.
func (s *Server) readBucketManifests(ctx context.Context, bucket, name string, prefixes []string) (map[string]int, error) {
	counts, left := map[string]int{}, manifestsPerTick
	for _, p := range prefixes {
		todo, err := s.index.ManifestsToRead(ctx, bucket, p, s.now(), left)
		if err != nil {
			return counts, err
		}
		left -= len(todo)
		for _, o := range todo {
			m := index.Manifest{Key: o.Key, ETag: o.ETag, Kind: index.KindNone, At: s.now()}
			var failed error
			if o.Size <= maxManifest {
				gctx, cancel := context.WithTimeout(ctx, manifestTimeout)
				body, ok, err := s.stores[name].Get(gctx, o.Key, maxManifest)
				cancel()
				switch {
				case err != nil:
					failed = err
				case !ok: // gone, or back with the same ETag before the next listing
					failed = errGone
				default:
					m = index.Parse(o.Key, o.ETag, body)
					m.At = s.now()
				}
			}
			if failed != nil {
				m.Kind = index.KindUnread
			}
			if err := s.index.PutManifest(ctx, bucket, m); err != nil {
				return counts, err
			}
			counts[m.Kind]++
			if failed != nil {
				return counts, fmt.Errorf("%s: %v", o.Key, failed)
			}
		}
	}
	return counts, nil
}

var errGone = errors.New("not found")
