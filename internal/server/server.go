// SPDX-License-Identifier: Apache-2.0

// Package server answers store requests: it checks the path and token
// (docs/TOKEN.md), redirects GET and HEAD to presigned URLs, takes writes
// through staging (upload.go) and fetches missing sources (fetch.go).
package server

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

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
	uploads     *uploadTable
	fetches     *fetchTable
	policy      *fetchPolicy
	fetchClient *http.Client
	plain       map[string]objectStore // volume -> plain URLs, for public bindings
	accessLog   string
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
	s := &Server{verifier: v, bindings: bs, stores: map[string]objectStore{}, place: map[string]string{},
		urlLife: life, now: time.Now, uploads: &uploadTable{}, fetches: &fetchTable{},
		policy: pol, fetchClient: pol.client(), plain: map[string]objectStore{}, accessLog: accessLog}
	for name, vol := range c.Volumes {
		s.place[name] = normEndpoint(vol.Endpoint) + " " + vol.Bucket
		s.plain[name] = plainStore{strings.TrimSuffix(vol.Endpoint, "/"), vol.Bucket}
		if s.stores[name], err = vol.store(); err != nil {
			return nil, fmt.Errorf("volume %q: %v", name, err)
		}
	}
	for _, b := range bs {
		// public bindings read by plain URLs; a fetching one has keys, to write
		anon := s.stores[b.Volume].Anonymous()
		switch {
		case b.mirror != nil && anon:
			return nil, fmt.Errorf("binding %q: format %s fetches, so it needs a volume with keys", b.Prefix, b.Format)
		case b.mirror == nil && b.Public != anon:
			return nil, fmt.Errorf("binding %q: public bindings need an anonymous volume, private ones a volume with keys", b.Prefix)
		}
	}
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code, t, p := s.serve(w, r)
	switch {
	case p == "/health" && code == http.StatusOK, s.accessLog == "none":
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

func (s *Server) serve(w http.ResponseWriter, r *http.Request) (code int, t *token.Token, p string) {
	// The path exactly as sent, never Go's decoded r.URL.Path (docs/TOKEN.md).
	p, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	if p == "/health" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		fmt.Fprintln(w, "ok")
		return http.StatusOK, nil, p
	}
	write := r.Method == http.MethodPost
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !write {
		w.Header().Set("Allow", "GET, HEAD, POST")
		return fail(w, http.StatusMethodNotAllowed), nil, p
	}
	segs, err := token.ParsePath(p)
	if err != nil {
		return fail(w, http.StatusBadRequest), nil, p
	}
	b, key := s.resolve(segs)
	now := s.now()
	// a public fetching binding reads without a token; asking for a fetch takes one
	fetchAsk := !write && b != nil && b.mirror != nil && rawQuery != "" && bearer(r) != ""
	if b == nil || !b.Public || write || fetchAsk {
		// the token comes before 404, so no one learns the bindings without one
		tok := bearer(r)
		if tok == "" {
			return fail(w, http.StatusUnauthorized), nil, p
		}
		if t, err = s.verify(tok, now); err != nil {
			log.Printf("%s %s %q: %v", r.RemoteAddr, r.Method, p, err) // logged, never sent back
			return fail(w, http.StatusUnauthorized), nil, p
		}
		if b == nil {
			return fail(w, http.StatusNotFound), t, p
		}
		method := r.Method
		if write {
			method = http.MethodPut
		}
		if !t.Allows(method, segs) && !(fetchAsk && b.Public) {
			return fail(w, http.StatusForbidden), t, p
		}
		if !t.Allows(method, segs) {
			t = nil // a public read, without the fetch the token may not ask for
		}
	}
	if key == "" {
		return fail(w, http.StatusNotFound), t, p // the binding's format found nothing
	}
	if write {
		if b.Public {
			return fail(w, http.StatusMethodNotAllowed), t, p
		}
		return s.write(w, r, rawQuery, b, key, t, now), t, p
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
	w.Header().Set("Location", loc)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
	return http.StatusFound
}

// resolve finds the binding with the longest prefix and the object key under
// it; the key is empty when the binding's format finds no object.
func (s *Server) resolve(segs []string) (*Binding, string) {
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
				return b, ""
			}
			if _, err := token.ParsePath("/" + it.Key); err != nil {
				log.Printf("format %s: bad key %q", b.Format, it.Key)
				return b, ""
			}
			if b.KeyPrefix == "" {
				return b, it.Key
			}
			return b, b.KeyPrefix + "/" + it.Key
		}
	}
	return nil, ""
}

// bearer returns the token: the Authorization header when there is one, else
// the cookie. A malformed header yields none, never the cookie.
func bearer(r *http.Request) string {
	if h := r.Header.Values("Authorization"); len(h) > 0 {
		scheme, tok, ok := strings.Cut(h[0], " ")
		if len(h) != 1 || !ok || !strings.EqualFold(scheme, "Bearer") {
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
