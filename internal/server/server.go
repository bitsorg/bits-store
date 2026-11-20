// SPDX-License-Identifier: Apache-2.0

// Package server answers store requests: it checks the path and token
// (docs/TOKEN.md), redirects GET and HEAD to presigned URLs, takes writes
// through staging (upload.go) and fetches missing sources (fetch.go).
package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
	"github.com/bitsorg/bits-store/internal/token"
)

const (
	cookieName   = "__Host-bits_store_token"
	maxCached    = 10000
	minURLExpiry = time.Second
)

// Server is safe for concurrent requests: the token cache and the upload and
// fetch tables have their own locks; the rest is read-only after New. A reload
// builds a new Server sharing those tables (Reloader).
type Server struct {
	verifier    *token.Verifier
	bindings    []Binding
	stores      map[string]objectStore
	place       map[string]string // volume -> its endpoint and bucket, for upload leases
	urlLife     time.Duration
	now         func() time.Time
	cache       tokenCache
	found       foundCache
	markers     markerCache
	uploads     *uploadTable
	fetches     *fetchTable
	meters      *meters // what the service does, for /metrics
	policy      *fetchPolicy
	fetchClient *http.Client
	plain       map[string]objectStore // volume -> plain URLs, for public bindings
	accessLog   string
	health      *volumeHealth
	scrape      refreshed[string] // /metrics' answer
	summary     refreshed[[]byte] // the admin API's
	keptBy      keptCache         // the admin API's: the collection's verdicts
	access      Access            // the admin API's: the configuration in force, without secrets
	index       *index.Index      // nil: none (no -data)
	verifyEvery time.Duration     // how often a bucket is listed against the index

	manifestKeys index.Keys   // the common manifests' signing keys
	reads        *readTable   // GETs redirected, for the index
	signer       *proxySigner // signs a gated binding's builds; nil: none
	withdrawn    *withdrawals // builds withdrawn through the admin API; nil: none (no -data)
	pages        *pageCache   // pypi bindings' pages
	git          *gitShared   // git bindings' repositories
	gc           *gcJobs      // the admin API's collections; nil: none (no -data)
}

// New builds a Server from a checked configuration.
func New(c *Config) (*Server, error) {
	v, err := c.verifier()
	if err != nil {
		return nil, err
	}
	bs, err := c.bindings()
	if err != nil {
		return nil, err
	}
	pol, err := newPolicy(c.Fetch)
	if err != nil {
		return nil, err
	}
	accessLog := c.AccessLog
	if accessLog == "" {
		accessLog = "errors"
	}
	if accessLog != "all" && accessLog != "errors" && accessLog != "none" {
		return nil, fmt.Errorf("access_log: all, errors or none")
	}
	life, err := duration(c.URLLifetime, 5*time.Minute)
	if err != nil || life < minURLExpiry || life > time.Hour {
		return nil, fmt.Errorf("url_lifetime: between 1s and 1h")
	}
	every, err := duration(c.IndexVerify, 24*time.Hour)
	if err != nil || every < time.Hour {
		return nil, fmt.Errorf("index_verify: at least 1h")
	}
	mkeys, err := index.ParseKeys(c.ManifestKeys)
	if err != nil {
		return nil, err
	}
	signer, err := newSigner(c.RestrictedSigner)
	if err != nil {
		return nil, err
	}
	for _, b := range bs {
		if b.Gate != "" && signer == nil {
			return nil, fmt.Errorf("binding %q: a gate needs restricted_signer, to sign its builds", b.Prefix)
		}
	}
	s := &Server{verifier: v, bindings: bs, stores: map[string]objectStore{}, place: map[string]string{},
		urlLife: life, now: time.Now, uploads: &uploadTable{}, fetches: &fetchTable{}, meters: newMeters(time.Now()),
		policy: pol, fetchClient: pol.client(), plain: map[string]objectStore{}, accessLog: accessLog,
		health: &volumeHealth{}, pages: &pageCache{}, git: &gitShared{refreshed: map[string]time.Time{}}, verifyEvery: every, manifestKeys: mkeys, reads: &readTable{}, signer: signer,
		access: accessOf(c, bs, mkeys)}
	for name, vol := range c.Volumes {
		s.place[name] = normEndpoint(vol.Endpoint) + " " + vol.Bucket
		s.plain[name] = plainStore{strings.TrimSuffix(vol.Endpoint, "/"), vol.Bucket}
		if s.stores[name], err = vol.store(); err != nil {
			return nil, fmt.Errorf("volume %q: %v", name, err)
		}
	}
	for _, b := range bs {
		// public bindings read by plain URLs; one that fetches or looks has keys
		anon := s.stores[b.Volume].Anonymous()
		keyed := b.mirror != nil || b.folder != nil || b.revisions != nil || b.Format == "pypi" || b.Format == "git"
		switch {
		case keyed && anon:
			return nil, fmt.Errorf("binding %q: format %s fetches or looks objects up, so it needs a volume with keys", b.Prefix, b.Format)
		case !keyed && b.Public != anon:
			return nil, fmt.Errorf("binding %q: public bindings need an anonymous volume, private ones a volume with keys", b.Prefix)
		}
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start, mw := time.Now(), &meterWriter{ResponseWriter: w}
	code, t, p := s.serve(mw, r)
	if p != "/health" && p != "/metrics" {
		s.meters.request(mw.b, r.Method, code, mw.n, time.Since(start))
	}
	switch {
	case p == "/health", p == "/metrics" && code == http.StatusOK, s.accessLog == "none": // a failing volume is logged by its probe
		return
	case s.accessLog == "errors" && code < 400 && r.Method != http.MethodPost:
		return // hits and waits; writes and errors are logged
	}
	who := "-"
	if t != nil {
		who = fmt.Sprintf("sub=%q grp=%q jti=%q", t.Sub, t.Grp, t.Jti)
	}
	log.Printf("%s %s %q %d %s", r.RemoteAddr, r.Method, p, code, who)
}

func fail(w http.ResponseWriter, c int) int {
	if c == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	http.Error(w, http.StatusText(c), c)
	return c
}

// errAdminToken: an admin key's token opens the admin API only, never a binding.
var errAdminToken = errors.New("an admin token outside the admin API")

func (s *Server) serve(w http.ResponseWriter, r *http.Request) (code int, t *token.Token, p string) {
	// The path exactly as sent, never Go's decoded r.URL.Path (docs/TOKEN.md).
	p, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	if p == "/health" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if bad := s.failingVolumes(s.now()); len(bad) > 0 { // why: in the log, not to anyone
			http.Error(w, "volumes failing: "+strings.Join(bad, ", "), http.StatusServiceUnavailable)
			return http.StatusServiceUnavailable, nil, p
		}
		fmt.Fprintln(w, "ok")
		return http.StatusOK, nil, p
	}
	if p == "/metrics" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		return s.metrics(w, r), nil, p // no token: for the site's own scraper, not the outside
	}
	write := r.Method == http.MethodPost
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !write {
		w.Header().Set("Allow", "GET, HEAD, POST")
		return fail(w, http.StatusMethodNotAllowed), nil, p
	}
	segs, err := token.ParsePath(p)
	if err != nil && strings.HasSuffix(p, "/") && !write { // pip asks a page as <index>/<project>/
		if s2, err2 := token.ParsePath(strings.TrimSuffix(p, "/")); err2 == nil {
			if pb, _, _ := s.resolve(s2); pb != nil && pb.Format == "pypi" {
				segs, err = s2, nil
			}
		}
	}
	if err != nil {
		return fail(w, http.StatusBadRequest), nil, p
	}
	b, key, dir := s.resolve(segs)
	if mw, ok := w.(*meterWriter); ok {
		mw.b = b // for the meters
	}
	now := s.now()
	if write && b != nil && b.Format == "git" && strings.HasSuffix(p, "/git-upload-pack") {
		write = false // git's fetch is a POST: a read
	}
	// a public fetching binding reads without a token; asking for a fetch takes one
	fetchAsk := !write && b != nil && b.mirror != nil && rawQuery != "" && bearer(r) != ""
	if b == nil || !b.Public || write || fetchAsk {
		// the token comes before 404, so no one learns the bindings without one
		tok := bearer(r)
		if tok == "" {
			return fail(w, http.StatusUnauthorized), nil, p
		}
		if t, err = s.verify(tok, now); err == nil && t.Signer == "admin" {
			err = errAdminToken
		}
		if err != nil {
			log.Printf("%s %s %q: %v", r.RemoteAddr, r.Method, p, err) // logged, never sent back
			return fail(w, http.StatusUnauthorized), nil, p
		}
		if b == nil {
			return fail(w, http.StatusNotFound), t, p
		}
		method := r.Method
		if write {
			method = http.MethodPut
		} else if method == http.MethodPost {
			method = http.MethodGet // git's fetch
		}
		if !t.Allows(method, segs) && !(fetchAsk && b.Public) {
			return fail(w, http.StatusForbidden), t, p
		}
		if !t.Allows(method, segs) {
			t = nil // a public read, without the fetch the token may not ask for
		}
	}
	if key == "" && dir == "" || b.Gate != "" && dir == "" {
		return fail(w, http.StatusNotFound), t, p // the binding's format found nothing; a gate holds builds
	}
	if b.Format == "git" {
		return s.serveGit(w, r, b, key, p, t, now), t, p
	}
	if b.Format == "pypi" {
		if write {
			return fail(w, http.StatusMethodNotAllowed), t, p // its files come from the index only
		}
		return s.servePyPI(w, r, b, key, t, now), t, p
	}
	if write && b.Gate != "" {
		if !groupName.MatchString(t.Grp) {
			return fail(w, http.StatusForbidden), t, p // no group to file it under
		}
		b, dir = within(b, t.Grp, dir)
	}
	if write {
		if s.stores[b.Volume].Anonymous() {
			return fail(w, http.StatusMethodNotAllowed), t, p // nothing to write with
		}
		return s.write(w, r, rawQuery, b, key, dir, t, now), t, p
	}
	if q, err := url.ParseQuery(rawQuery); b.revisions != nil && err == nil && len(q) == 1 && q.Has("revisions") {
		return s.answerRevisions(w, r, b, key, segs), t, p
	}
	if dir != "" {
		var group string // a gated build's: its folder, what its signature names (not its metadata)
		if b.Gate != "" {
			b, key, group, err = s.gatedLookup(r.Context(), b, t, dir, now)
		} else {
			key, err = s.found.lookup(r.Context(), s, b, dir, now)
		}
		if err != nil {
			log.Printf("list %s: %v", dir, err)
			return fail(w, http.StatusBadGateway), t, p
		} else if key == "" {
			return fail(w, http.StatusNotFound), t, p
		}
		w.Header().Set("Bits-Object-Name", path.Base(key))
		if group != "" {
			w.Header().Set("Bits-Object-Group", group)
		}
	}
	if b.mirror != nil && rawQuery != "" && t != nil {
		return s.fetchRead(w, r, rawQuery, b, key, t, now), t, p
	}
	return s.redirect(w, r, b, key, t, now), t, p
}

// redirect answers a read with a presigned URL for key.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, b *Binding, key string, t *token.Token, now time.Time) int {
	expiry := s.urlLife
	if t != nil {
		if left := time.Unix(t.Exp, 0).Sub(now); left < expiry {
			expiry = max(left, minURLExpiry) // a URL never outlives its token
		}
	}
	st := s.stores[b.Volume]
	if b.Public {
		st = s.plain[b.Volume] // never the service's keys
	}
	loc, err := st.Presign(r.Context(), r.Method, key, expiry, nil)
	if err != nil {
		log.Printf("presign %s: %v", key, err)
		return fail(w, http.StatusBadGateway)
	}
	if s.index != nil && r.Method == http.MethodGet {
		s.reads.add(s.place[b.Volume], key, now)
	}
	w.Header().Set("Location", loc)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
	return http.StatusFound
}

// resolve finds the binding with the longest prefix and the object key, or the
// folder holding it (format.Item), under it; both empty when the format finds none.
func (s *Server) resolve(segs []string) (*Binding, string, string) {
	for i := range s.bindings {
		b := &s.bindings[i]
		if len(segs) <= len(b.segs) {
			continue
		}
		match := true
		for k, seg := range b.segs {
			if segs[k] != seg {
				match = false
				break
			}
		}
		if match {
			// a format's key stays within the path rules, so under its key prefix
			it, err := b.format.Route(slices.Clone(segs[len(b.segs):]))
			if err != nil {
				return b, "", ""
			}
			if (it.Key == "") == (it.Dir == "") || it.Dir != "" && b.folder == nil {
				log.Printf("format %s: neither a key nor a folder of its own", b.Format)
				return b, "", ""
			}
			if _, err := token.ParsePath("/" + it.Key + it.Dir); err != nil {
				log.Printf("format %s: bad key %q", b.Format, it.Key+it.Dir)
				return b, "", ""
			}
			pre := ""
			if b.KeyPrefix != "" {
				pre = b.KeyPrefix + "/"
			}
			if it.Dir != "" {
				return b, "", pre + it.Dir
			}
			return b, pre + it.Key, ""
		}
	}
	return nil, "", ""
}

// lookup returns the object stored in a folder, "" for none; of several (old
// stores), the one its format picks, the same on every copy of the store.
func (s *Server) lookup(ctx context.Context, b *Binding, dir string) (string, error) {
	keys, err := s.stores[b.Volume].List(ctx, dir+"/")
	if err != nil || len(keys) == 0 {
		return "", err
	}
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = path.Base(k)
	}
	return dir + "/" + b.folder.First(names), nil
}

// others reports whether a folder holds an object other than key.
func (s *Server) others(ctx context.Context, volume, dir, key string) (bool, error) {
	keys, err := s.stores[volume].List(ctx, dir+"/")
	return slices.ContainsFunc(keys, func(k string) bool { return k != key }), err
}

// foundCache spares reads a listing: an object found is kept for foundTTL, a
// miss for missTTL (apart, so misses never flush hits), unless this instance
// stores one. Writes never use it.
type foundCache struct {
	mu           sync.Mutex
	hits, misses map[string]foundEntry
}

type foundEntry struct {
	key   string
	until time.Time
}

const (
	foundTTL = 10 * time.Minute // a deleted object (GC) is noticed after this
	missTTL  = 30 * time.Second
	maxFound = 100000
)

func (c *foundCache) lookup(ctx context.Context, s *Server, b *Binding, dir string, now time.Time) (string, error) {
	k := s.place[b.Volume] + "\x00" + dir
	c.mu.Lock()
	e, hit := c.hits[k]
	m, miss := c.misses[k]
	c.mu.Unlock()
	switch {
	case hit && now.Before(e.until):
		return e.key, nil
	case miss && now.Before(m.until):
		return "", nil
	}
	key, err := s.lookup(ctx, b, dir)
	if err != nil {
		return "", err
	}
	if key != "" {
		c.set(k, key, now)
	} else { // a hit, from a store here meanwhile, still comes first
		c.mu.Lock()
		c.misses = bounded(c.misses)
		c.misses[k] = foundEntry{"", now.Add(missTTL)}
		c.mu.Unlock()
	}
	return key, nil
}

// forget drops the hit on key of the bucket at (found in its folder): deleted here.
func (c *foundCache) forget(at, key string) {
	k := at + "\x00" + path.Dir(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hits[k].key == key {
		delete(c.hits, k)
	}
}

// stored records an object this instance stored in a folder.
func (c *foundCache) stored(s *Server, volume, dir, key string, now time.Time) {
	c.set(s.place[volume]+"\x00"+dir, key, now)
}

func (c *foundCache) set(k, key string, now time.Time) {
	c.mu.Lock()
	c.hits = bounded(c.hits)
	c.hits[k] = foundEntry{key, now.Add(foundTTL)}
	delete(c.misses, k)
	c.mu.Unlock()
}

// bounded is m, or a new map when m is missing or full: a simple bound.
func bounded(m map[string]foundEntry) map[string]foundEntry {
	if m == nil || len(m) >= maxFound {
		return map[string]foundEntry{}
	}
	return m
}

// bearer returns the token: the Authorization header when there is one, else
// the cookie. A malformed header yields none, never the cookie.
func bearer(r *http.Request) string {
	if h := r.Header.Values("Authorization"); len(h) > 0 {
		scheme, tok, ok := strings.Cut(h[0], " ")
		if len(h) != 1 || !ok {
			return ""
		}
		if strings.EqualFold(scheme, "Basic") && (r.Method == http.MethodGet || r.Method == http.MethodHead) { // pip: the token as the password
			_, tok, ok = r.BasicAuth()
			if !ok {
				return ""
			}
		} else if !strings.EqualFold(scheme, "Bearer") {
			return ""
		}
		return tok
	}
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

// tokenCache remembers verified tokens until they expire, so repeated requests
// skip the signature check. A deny-list, when added, must be checked on hits too.
type tokenCache struct {
	mu sync.Mutex
	m  map[[32]byte]*token.Token
}

func (s *Server) verify(tok string, now time.Time) (*token.Token, error) {
	h := sha256.Sum256([]byte(tok))
	s.cache.mu.Lock()
	t, ok := s.cache.m[h]
	s.cache.mu.Unlock()
	if ok && now.Unix() <= t.Exp+token.Leeway {
		return t, nil
	}
	t, err := s.verifier.Verify(tok, now)
	if err != nil {
		return nil, err
	}
	s.cache.mu.Lock()
	if s.cache.m == nil || len(s.cache.m) >= maxCached {
		s.cache.m = map[[32]byte]*token.Token{} // simple bound: start over
	}
	s.cache.m[h] = t
	s.cache.mu.Unlock()
	return t, nil
}
