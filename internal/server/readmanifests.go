// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
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
			log.Printf("index: volume %q: manifests read: %d BOMs, %d common (%d verified), %d others",
				name, counts[index.KindBOM], counts[index.KindCommon], counts["verified"], counts[index.KindNone])
		}
		if err != nil {
			s.warnf("manifests_unread", name, "index: volume %q: manifests not read, again in %s: %v", name, index.RetryUnread, err)
		}
	}
}

// readBucketManifests reads up to manifestsPerTick files of a bucket, by kind; at
// the first that cannot be read (noted as unread) the bucket waits for the next tick.
func (s *Server) readBucketManifests(ctx context.Context, bucket, name string, prefixes []string) (map[string]int, error) {
	counts, left, keys := map[string]int{}, manifestsPerTick, s.manifestKeys.IDs()
	for _, p := range prefixes {
		todo, err := s.index.ManifestsToRead(ctx, bucket, p, keys, s.now(), left)
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
					if m.Kind == index.KindCommon {
						m.SigETag, m.Keys = o.SigETag, keys
						m.VerifiedBy, failed = s.verifyCommon(ctx, name, o, body)
					}
				}
			}
			if failed != nil { // nothing of it until read
				m = index.Manifest{Key: o.Key, ETag: o.ETag, Kind: index.KindUnread, At: s.now()}
			}
			if err := s.index.PutManifest(ctx, bucket, m); err != nil {
				return counts, err
			}
			counts[m.Kind]++
			if m.VerifiedBy != "" {
				counts["verified"]++
			}
			if failed != nil {
				return counts, fmt.Errorf("%s: %v", o.Key, failed)
			}
		}
	}
	return counts, nil
}

var errGone = errors.New("not found")

// verifyCommon checks a common manifest's .sig with the manifest keys: the key that
// made it, or "" (no keys, no .sig, not theirs).
func (s *Server) verifyCommon(ctx context.Context, name string, o index.ToRead, body []byte) (string, error) {
	if len(s.manifestKeys) == 0 || o.SigETag == "" {
		return "", nil
	}
	gctx, cancel := context.WithTimeout(ctx, manifestTimeout)
	defer cancel()
	sig, ok, err := s.stores[name].Get(gctx, o.Key+".sig", 64<<10)
	if err != nil || !ok {
		return "", cmp.Or(err, errGone)
	}
	return s.manifestKeys.Verify(body, sig), nil
}
