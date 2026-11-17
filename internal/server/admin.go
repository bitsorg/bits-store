// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
	"github.com/bitsorg/bits-store/internal/token"
)

// The admin API: its own listener (-admin-listen), for bits-console's admin pages.
const (
	adminPrefix   = "/_admin/"
	adminLifetime = 15 * time.Minute // the longest an admin token may live
	readLately    = 30 * 24 * time.Hour
)

// ServeAdmin answers the admin API with the current Server.
func (r *Reloader) ServeAdmin(w http.ResponseWriter, req *http.Request) {
	r.cur.Load().ServeAdmin(w, req)
}

// ServeAdmin answers /_admin/ to an admin key's token allowed the path, logging each request.
func (s *Server) ServeAdmin(w http.ResponseWriter, r *http.Request) {
	code, t, p := s.serveAdmin(w, r)
	who := "-"
	if t != nil {
		who = fmt.Sprintf("sub=%q jti=%q", t.Sub, t.Jti)
	}
	log.Printf("admin %s %s %q %d %s", r.RemoteAddr, r.Method, p, code, who)
}

func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) (int, *token.Token, string) {
	p, _, _ := strings.Cut(r.RequestURI, "?")
	if !strings.HasPrefix(p, adminPrefix) {
		return fail(w, http.StatusNotFound), nil, p
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		return fail(w, http.StatusMethodNotAllowed), nil, p
	}
	segs, err := token.ParsePath(p)
	if err != nil {
		return fail(w, http.StatusBadRequest), nil, p
	}
	scheme, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ") // the header only, never a cookie
	if !strings.EqualFold(scheme, "Bearer") || len(r.Header.Values("Authorization")) != 1 {
		return fail(w, http.StatusUnauthorized), nil, p
	}
	t, err := s.verify(tok, s.now())
	switch {
	case err != nil:
		log.Printf("admin %s %s %q: %v", r.RemoteAddr, r.Method, p, err)
		return fail(w, http.StatusUnauthorized), nil, p
	case t.Signer != "admin" || time.Duration(t.Exp-t.Iat)*time.Second > adminLifetime:
		log.Printf("admin %s %s %q: not an admin key's token of %v at most", r.RemoteAddr, r.Method, p, adminLifetime)
		return fail(w, http.StatusUnauthorized), nil, p
	case !t.Allows(r.Method, segs):
		return fail(w, http.StatusForbidden), t, p
	}
	switch p {
	case adminPrefix + "summary":
		return s.adminSummary(w, r), t, p
	}
	return fail(w, http.StatusNotFound), t, p
}

// Summary is what the store holds, by volume and binding, from the index.
type Summary struct {
	At         time.Time       `json:"at"`
	ReadsSince *time.Time      `json:"reads_since"` // when reads began to be counted; nil: not yet
	Volumes    []VolumeSummary `json:"volumes"`
	Errors     int64           `json:"index_errors"`
}

// VolumeSummary is one bucket (named by its first volume) and its bindings.
type VolumeSummary struct {
	Volume   string           `json:"volume"`
	Where    string           `json:"where"`   // the endpoint and bucket
	Indexed  bool             `json:"indexed"` // an anonymous volume is not
	Listed   *time.Time       `json:"listed"`  // when its last listing began; nil: never
	Drift    *Drift           `json:"drift"`
	Objects  int64            `json:"objects"`
	Bytes    int64            `json:"bytes"`
	Bindings []BindingSummary `json:"bindings"`
}

// Drift is what the last listing found the index to differ in.
type Drift struct {
	Missing int64 `json:"missing"` // listed, not indexed
	Changed int64 `json:"changed"` // listed otherwise
	Extra   int64 `json:"extra"`   // indexed, not listed
}

// BindingSummary is a binding's objects; a tarballs binding's by architecture (a
// gated one's by group/architecture), with those a certified build lists.
type BindingSummary struct {
	Prefix     string  `json:"prefix"`
	KeyPrefix  string  `json:"key_prefix"`
	Format     string  `json:"format"`
	Public     bool    `json:"public"`
	Gate       string  `json:"gate,omitempty"`
	Objects    int64   `json:"objects"`
	Bytes      int64   `json:"bytes"`
	ReadLately int64   `json:"read_lately"` // objects read in the last 30 days
	Certified  *Tally  `json:"certified,omitempty"`
	By         []Tally `json:"by,omitempty"`
}

// Tally counts objects and their bytes.
type Tally struct {
	Name    string `json:"name,omitempty"`
	Objects int64  `json:"objects"`
	Bytes   int64  `json:"bytes"`
}

// summaryCache is the last summary: one computation at a time, kept a minute.
type summaryCache struct {
	mu   sync.Mutex
	at   time.Time
	body []byte
}

func (s *Server) adminSummary(w http.ResponseWriter, r *http.Request) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	c := &s.summary
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := s.now(); c.body == nil || now.Sub(c.at) >= metricsEvery || now.Before(c.at) {
		sum, err := s.summarize(r.Context(), now)
		if err != nil {
			log.Printf("admin summary: %v", err)
			return fail(w, http.StatusInternalServerError)
		}
		b, _ := json.Marshal(sum)
		c.at, c.body = now, b
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(c.body)
	return http.StatusOK
}

func (s *Server) summarize(ctx context.Context, now time.Time) (*Summary, error) {
	sum := &Summary{At: now.UTC(), Errors: s.index.Errors(), Volumes: []VolumeSummary{}}
	if since, err := s.index.ReadsSince(ctx); err != nil {
		return nil, err
	} else if !since.IsZero() {
		since = since.UTC()
		sum.ReadsSince = &since
	}
	first := map[string]string{} // bucket -> its first volume by name, one with keys if any (as /metrics)
	for _, n := range slices.Sorted(maps.Keys(s.stores)) {
		if f, ok := first[s.place[n]]; !ok || s.stores[f].Anonymous() && !s.stores[n].Anonymous() {
			first[s.place[n]] = n
		}
	}
	for _, at := range slices.Sorted(maps.Values(first)) {
		v, err := s.summarizeVolume(ctx, at, now)
		if err != nil {
			return nil, err
		}
		sum.Volumes = append(sum.Volumes, v)
	}
	return sum, nil
}

func (s *Server) summarizeVolume(ctx context.Context, name string, now time.Time) (VolumeSummary, error) {
	bucket := s.place[name]
	v := VolumeSummary{Volume: name, Where: bucket, Indexed: !s.stores[name].Anonymous(), Bindings: []BindingSummary{}}
	var owner map[[2]string]string
	if v.Indexed {
		at, d, ok, err := s.index.Verified(ctx, bucket)
		if err != nil {
			return v, err
		}
		if ok {
			at = at.UTC()
			v.Listed, v.Drift = &at, &Drift{d.Missing, d.Changed, d.Extra}
		}
		c, err := s.index.Total(ctx, bucket)
		if err != nil {
			return v, err
		}
		v.Objects, v.Bytes = c.Objects, c.Bytes
		if owner, _, err = s.index.Certified(ctx, bucket, s.manifestKeys.IDs()); err != nil {
			return v, err
		}
	}
	for _, b := range s.bindings {
		if s.place[b.Volume] != bucket {
			continue
		}
		bs := BindingSummary{Prefix: b.Prefix, KeyPrefix: b.KeyPrefix, Format: b.Format, Public: b.Public, Gate: b.Gate}
		if v.Indexed {
			if err := s.summarizeBinding(ctx, bucket, &b, owner, now, &bs); err != nil {
				return v, err
			}
		}
		v.Bindings = append(v.Bindings, bs)
	}
	slices.SortFunc(v.Bindings, func(a, b BindingSummary) int { return strings.Compare(a.Prefix, b.Prefix) })
	return v, nil
}

// summarizeBinding counts the objects under b's key prefix in one query; a tarballs
// binding's, row by row as /metrics, by architecture (<arch>/store/<h2>/<hash>/<file>;
// behind a gate <group>/ first).
func (s *Server) summarizeBinding(ctx context.Context, bucket string, b *Binding, owner map[[2]string]string,
	now time.Time, bs *BindingSummary) error {
	p := strings.TrimSuffix(b.KeyPrefix, "/")
	c, read, err := s.index.Tally(ctx, bucket, p, now.Add(-readLately))
	bs.Objects, bs.Bytes, bs.ReadLately = c.Objects, c.Bytes, read
	if err != nil || b.Format != "tarballs" {
		return err
	}
	skip := len(p) + 1
	if p == "" {
		skip = 0
	}
	if b.Gate == "" {
		bs.Certified = &Tally{}
	}
	by := map[string]*Tally{}
	err = s.index.Each(ctx, bucket, p, func(o index.Object) {
		if len(o.Key) <= skip {
			return
		}
		rest := o.Key[skip:]
		name := ""
		if b.Gate != "" {
			grp, k, _ := strings.Cut(rest, "/")
			arch, _, _ := strings.Cut(k, "/")
			if grp == "" || arch == "" {
				return // as /metrics: under no architecture
			}
			name = grp + "/" + arch
		} else {
			seg := strings.SplitN(rest, "/", 6)
			if name = seg[0]; name == "" {
				return
			}
			if len(seg) >= 5 && seg[1] == "store" && owner[[2]string{seg[0], seg[3]}] != "" {
				bs.Certified.Objects, bs.Certified.Bytes = bs.Certified.Objects+1, bs.Certified.Bytes+o.Size
			}
		}
		t := by[name]
		if t == nil {
			t = &Tally{Name: name}
			by[name] = t
		}
		t.Objects, t.Bytes = t.Objects+1, t.Bytes+o.Size
	})
	for _, n := range slices.Sorted(maps.Keys(by)) {
		bs.By = append(bs.By, *by[n])
	}
	slices.SortStableFunc(bs.By, func(a, b Tally) int { return cmp.Compare(b.Bytes, a.Bytes) })
	return err
}
