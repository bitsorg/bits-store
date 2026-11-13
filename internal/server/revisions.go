// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// A marker's revision and hash, as bits writes them (bits rev_index).
var (
	revisionName = regexp.MustCompile(`^([0-9]+|local[0-9]+|[0-9a-fA-F]{40})$`)
	markerHash   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

const maxMarker = 256 // bytes of a marker read: a hash and a newline

// markerCache keeps markers read for foundTTL: written once, but bits' own tools may
// delete and rewrite them.
type markerCache struct {
	mu sync.Mutex
	m  map[string]foundEntry // bucket and key -> hash
}

// answerRevisions answers GET <path>?revisions with {revision: hash} from the
// markers <key>-<revision> (format.Revisions), one listing; the index later.
func (s *Server) answerRevisions(w http.ResponseWriter, r *http.Request, b *Binding, key string, segs []string) int {
	if b.revisions.RevisionsOf(slices.Clone(segs[len(b.segs):])) != nil {
		return fail(w, http.StatusNotFound)
	}
	st := s.stores[b.Volume]
	keys, err := st.List(r.Context(), key+"-")
	if err != nil {
		log.Printf("list %s-: %v", key, err)
		return fail(w, http.StatusBadGateway)
	}
	out := map[string]string{}
	for _, k := range keys {
		rev := strings.TrimPrefix(k, key+"-")
		if !revisionName.MatchString(rev) {
			continue // another version's, or not a marker
		}
		h, err := s.markers.get(r, st, s.place[b.Volume], k, s.now())
		if err != nil {
			log.Printf("get %s: %v", k, err)
			return fail(w, http.StatusBadGateway)
		}
		if h != "" {
			out[rev] = h
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
	return http.StatusOK
}

// get is the hash a marker holds, "" when it holds none.
func (c *markerCache) get(r *http.Request, st objectStore, place, key string, now time.Time) (string, error) {
	ck := place + "\x00" + key
	c.mu.Lock()
	e, ok := c.m[ck]
	c.mu.Unlock()
	if ok && now.Before(e.until) {
		return e.key, nil
	}
	body, found, err := st.Get(r.Context(), key, maxMarker)
	if err != nil || !found {
		return "", err
	}
	h := strings.TrimSpace(string(body))
	if !markerHash.MatchString(h) {
		h = "" // not a marker
	}
	c.mu.Lock()
	c.m = bounded(c.m)
	c.m[ck] = foundEntry{h, now.Add(foundTTL)}
	c.mu.Unlock()
	return h, nil
}
