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
	"net/url"
	"path"
	"slices"
	"strconv"
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
	p, rawQuery, _ := strings.Cut(r.RequestURI, "?")
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
	case adminPrefix + "objects":
		return s.adminObjects(w, r, rawQuery), t, p
	case adminPrefix + "object":
		return s.adminObject(w, r, rawQuery), t, p
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

// keptCache is the collection's verdict (DefaultGC) on each package file of a bucket,
// by key: why it stays, or that it would go. Recomputed at most every keptEvery.
type keptCache struct {
	mu      sync.Mutex
	buckets map[string]*verdicts
}

// verdicts are a bucket's; its lock is held while they are planned.
type verdicts struct {
	mu  sync.Mutex
	at  time.Time
	why map[string]string
}

const (
	keptEvery = 5 * time.Minute
	keptTime  = 10 * time.Minute // the longest a plan for verdicts may take
)

// kept plans a bucket's packages as the collection would (refusals aside) and
// returns the verdicts; nil for a bucket without tarballs bindings.
func (s *Server) kept(ctx context.Context, bucket string) (map[string]string, error) {
	c := &s.keptBy
	c.mu.Lock()
	if c.buckets == nil {
		c.buckets = map[string]*verdicts{}
	}
	v := c.buckets[bucket]
	if v == nil {
		v = &verdicts{}
		c.buckets[bucket] = v
	}
	c.mu.Unlock()
	v.mu.Lock() // one plan of a bucket at a time; other buckets go on
	defer v.mu.Unlock()
	if v.why != nil && s.now().Sub(v.at) < keptEvery && !s.now().Before(v.at) {
		return v.why, nil
	}
	var prefixes []string
	grouped := false
	for _, b := range s.bindings {
		if b.Format == "tarballs" && s.place[b.Volume] == bucket && !s.stores[b.Volume].Anonymous() {
			prefixes, grouped = append(prefixes, strings.TrimSuffix(b.KeyPrefix, "/")), b.Gate != "" // a gated bucket holds gated bindings only
		}
	}
	if prefixes == nil {
		return nil, nil
	}
	// the plan outlives a request given up: the next one finds it
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keptTime)
	defer cancel()
	var roots, certified map[string]bool
	var err error
	if !grouped {
		if roots, certified, err = s.index.Roots(pctx, bucket, s.manifestKeys.IDs()); err != nil {
			return nil, err
		}
	}
	p := &GCPlan{bucket: bucket, why: map[string]string{}}
	if err := s.planTree(pctx, p, prefixes, grouped, roots, certified, DefaultGC); err != nil {
		return nil, err
	}
	v.at, v.why = s.now(), p.why
	return p.why, nil
}

// ObjectRow is one object a search found; a package's architecture, hash and file
// (and group behind a gate), and the collection's verdict on it.
type ObjectRow struct {
	Key     string     `json:"key"`
	Size    int64      `json:"size"`
	ETag    string     `json:"etag"`
	Written time.Time  `json:"written"`
	Reads   int64      `json:"reads"`
	ReadAt  *time.Time `json:"read_at"`
	Writer  string     `json:"writer,omitempty"` // the group whose token wrote it, when known
	Group   string     `json:"group,omitempty"`  // the folder behind a gate
	Arch    string     `json:"arch,omitempty"`
	Hash    string     `json:"hash,omitempty"`
	File    string     `json:"file,omitempty"`
	Kept    string     `json:"kept,omitempty"`
}

const searchLimit = 500 // rows an answer holds at most

var searchScan = 100000 // rows a search looks at, at most, before it answers with next

// adminObjects searches one binding (?binding=<prefix>) from the index: under a
// folder (under), by text in the key (q), manifest kind (kind), write date (since,
// before), the collection's verdict (kept); after a key (after), limit rows. Each
// filter is applied here, so searchScan bounds the rows looked at; the answer's next
// continues it ("" at the end).
func (s *Server) adminObjects(w http.ResponseWriter, r *http.Request, rawQuery string) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return failMsg(w, http.StatusBadRequest, "query")
	}
	b := s.binding(q.Get("binding"))
	if b == nil {
		return failMsg(w, http.StatusNotFound, "no such binding")
	}
	prefix := strings.TrimSuffix(b.KeyPrefix, "/")
	if u := q.Get("under"); u != "" {
		if _, err := token.ParsePath("/" + u); err != nil {
			return failMsg(w, http.StatusBadRequest, "under")
		}
		prefix = strings.TrimPrefix(prefix+"/"+u, "/")
	}
	text, after, kind, kept, limit := strings.ToLower(q.Get("q")), q.Get("after"), q.Get("kind"), q.Get("kept"), 100
	var since, before time.Time
	switch {
	case len(text) > 200:
		return failMsg(w, http.StatusBadRequest, "q")
	case after != "" && !strings.HasPrefix(after, strings.TrimPrefix(prefix+"/", "/")):
		return failMsg(w, http.StatusBadRequest, "after")
	case kind != "" && (b.Format != "manifests" || !slices.Contains([]string{index.KindBOM, index.KindCommon, "none"}, kind)):
		return failMsg(w, http.StatusBadRequest, "kind")
	case kept != "" && (b.Format != "tarballs" || !slices.Contains(whys, kept)):
		return failMsg(w, http.StatusBadRequest, "kept")
	}
	if n := q.Get("limit"); n != "" {
		if limit, err = strconv.Atoi(n); err != nil || limit < 1 || limit > searchLimit {
			return failMsg(w, http.StatusBadRequest, "limit")
		}
	}
	for name, t := range map[string]*time.Time{"since": &since, "before": &before} {
		if v := q.Get(name); v != "" {
			if *t, err = parseDay(v); err != nil {
				return failMsg(w, http.StatusBadRequest, name)
			}
		}
	}
	bucket := s.place[b.Volume]
	var verdicts map[string]string
	if b.Format == "tarballs" {
		if verdicts, err = s.kept(r.Context(), bucket); err != nil {
			log.Printf("admin objects: %v", err)
			return fail(w, http.StatusInternalServerError)
		}
	}
	rows, next, last, scanned := []ObjectRow{}, "", "", 0
	err = s.index.Search(r.Context(), bucket, prefix, after, func(o index.Object, k string) bool {
		if scanned++; scanned > searchScan {
			next = last // looked at enough: the rest after it
			return false
		}
		last = o.Key
		switch {
		case text != "" && !strings.Contains(strings.ToLower(o.Key), text),
			!since.IsZero() && o.Mtime.Before(since), !before.IsZero() && !o.Mtime.Before(before),
			kind != "" && k != kind,
			kept != "" && verdicts[o.Key] != kept:
			return true
		}
		row := objectRow(b, o, verdicts[o.Key])
		if len(rows) == limit {
			next = rows[limit-1].Key // a row more: the rest after the last one sent
			return false
		}
		rows = append(rows, row)
		return true
	})
	if err != nil {
		log.Printf("admin objects: %v", err)
		return fail(w, http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"objects": rows, "next": next})
	return http.StatusOK
}

// objectRow is o of binding b as the admin API shows it, with the verdict kept.
func objectRow(b *Binding, o index.Object, kept string) ObjectRow {
	row := ObjectRow{Key: o.Key, Size: o.Size, ETag: o.ETag, Written: o.Mtime.UTC(), Reads: o.Reads,
		Writer: o.Grp, Kept: kept}
	if !o.ReadAt.IsZero() {
		at := o.ReadAt.UTC()
		row.ReadAt = &at
	}
	skip := len(strings.TrimSuffix(b.KeyPrefix, "/")) + 1
	if b.KeyPrefix == "" {
		skip = 0
	}
	if b.Format == "tarballs" && len(o.Key) > skip {
		rest := o.Key[skip:]
		if b.Gate != "" {
			row.Group, rest, _ = strings.Cut(rest, "/")
		}
		if m := packageKey.FindStringSubmatch(rest); m != nil {
			row.Arch, row.Hash, row.File = m[1], m[3], path.Base(rest)
		}
	}
	return row
}

var whys = []string{WhyListed, WhyUncert, WhyYoung, WhyRead, WhyNewest, WhyOther, WhyGoes}

// parseDay reads a date (2006-01-02, UTC) or an RFC 3339 time.
func parseDay(v string) (time.Time, error) {
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, v)
}

// ObjectDetail is one object: as a search shows it, with its SHA-256; its metadata
// in the bucket (a HEAD); a package's manifests (BOMs and common manifests listing
// its hash); a manifest's kind and builds, as the index read them.
type ObjectDetail struct {
	ObjectRow
	SHA256   string            `json:"sha256,omitempty"`
	InBucket *bool             `json:"in_bucket"`           // nil: the bucket did not answer
	Meta     map[string]string `json:"meta,omitempty"`      // its user metadata there (bits-group, bits-signature, sha256, ...)
	ListedBy []index.Listing   `json:"listed_by,omitempty"` // a package's
	Kind     string            `json:"kind,omitempty"`      // a manifest's: bom, common, none
	Builds   []string          `json:"builds,omitempty"`    // a BOM's build, a common manifest's sources
}

// adminObject answers one object of a binding (?binding=<prefix>&key=<key>).
func (s *Server) adminObject(w http.ResponseWriter, r *http.Request, rawQuery string) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return failMsg(w, http.StatusBadRequest, "query")
	}
	b := s.binding(q.Get("binding"))
	key := q.Get("key")
	if b == nil {
		return failMsg(w, http.StatusNotFound, "no such binding")
	}
	if p := strings.TrimSuffix(b.KeyPrefix, "/"); p != "" && !strings.HasPrefix(key, p+"/") || key == "" {
		return failMsg(w, http.StatusBadRequest, "key")
	}
	ctx, bucket := r.Context(), s.place[b.Volume]
	o, ok, err := s.index.Get(ctx, bucket, key)
	if err != nil {
		log.Printf("admin object: %v", err)
		return fail(w, http.StatusInternalServerError)
	} else if !ok {
		return fail(w, http.StatusNotFound)
	}
	o.Key = key
	var verdicts map[string]string
	if b.Format == "tarballs" {
		if verdicts, err = s.kept(ctx, bucket); err != nil {
			log.Printf("admin object: %v", err)
			return fail(w, http.StatusInternalServerError)
		}
	}
	d := ObjectDetail{ObjectRow: objectRow(b, o, verdicts[key]), SHA256: o.SHA256}
	if d.Hash != "" {
		if d.ListedBy, err = s.index.ListedBy(ctx, bucket, d.Arch, d.Hash, s.manifestKeys.IDs()); err != nil {
			log.Printf("admin object: %v", err)
			return fail(w, http.StatusInternalServerError)
		}
	}
	if b.Format == "manifests" {
		if d.Kind, d.Builds, err = s.index.Builds(ctx, bucket, key); err != nil {
			log.Printf("admin object: %v", err)
			return fail(w, http.StatusInternalServerError)
		}
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	fi, found, err := s.stores[b.Volume].Stat(sctx, key)
	cancel()
	if err != nil {
		log.Printf("admin object: stat %s: %v", key, err) // shown as not known: nil
	} else {
		d.InBucket, d.Meta = &found, fi.Meta
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(d)
	return http.StatusOK
}

// binding is the binding of exactly that prefix, nil when none.
func (s *Server) binding(prefix string) *Binding {
	for i := range s.bindings {
		if s.bindings[i].Prefix == prefix {
			return &s.bindings[i]
		}
	}
	return nil
}
