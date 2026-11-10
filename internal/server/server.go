// SPDX-License-Identifier: Apache-2.0

// Package server answers store requests: it checks the path and token
// (docs/TOKEN.md) and redirects GET and HEAD to presigned S3 URLs.
package server

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"

	"github.com/bitsorg/bits-store/internal/token"
)

const (
	cookieName   = "__Host-bits_store_token"
	maxCached    = 10000
	minURLExpiry = time.Second
)

// Server is safe for concurrent requests: everything but the token cache is
// read-only after New.
type Server struct {
	verifier *token.Verifier
	bindings []Binding
	clients  map[string]*minio.Client // nil: an anonymous volume, served by plain URL
	volumes  map[string]VolumeConf
	urlLife  time.Duration
	now      func() time.Time
	cache    tokenCache
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
	life, err := duration(c.URLLifetime, 5*time.Minute)
	if err != nil || life < minURLExpiry || life > time.Hour {
		return nil, fmt.Errorf("url_lifetime: between 1s and 1h")
	}
	s := &Server{verifier: v, bindings: bs, clients: map[string]*minio.Client{},
		volumes: c.Volumes, urlLife: life, now: time.Now}
	for name, vol := range c.Volumes {
		if s.clients[name], err = vol.client(); err != nil {
			return nil, fmt.Errorf("volume %q: %v", name, err)
		}
	}
	for _, b := range bs {
		// a public binding must never presign with the service's keys
		if b.Public != (s.clients[b.Volume] == nil) {
			return nil, fmt.Errorf("binding %q: public bindings need an anonymous volume, private ones a volume with keys", b.Prefix)
		}
	}
	return s, nil
}

func (v VolumeConf) client() (*minio.Client, error) {
	u, err := url.Parse(v.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" && u.Path != "/" || !(u.Scheme == "https" || u.Scheme == "http" && v.AllowHTTP) {
		return nil, fmt.Errorf("endpoint: an https://host URL needed (http only with allow_http)")
	}
	if s3utils.CheckValidBucketNameStrict(v.Bucket) != nil || v.Region == "" {
		return nil, fmt.Errorf("a valid bucket and a region needed (the region spares a lookup)")
	}
	if v.AccessKeyEnv == "" && v.SecretKeyEnv == "" {
		return nil, nil // anonymous: public objects only
	}
	ak, sk := os.Getenv(v.AccessKeyEnv), os.Getenv(v.SecretKeyEnv)
	if ak == "" || sk == "" {
		return nil, fmt.Errorf("%s or %s is empty", v.AccessKeyEnv, v.SecretKeyEnv)
	}
	creds := credentials.NewStaticV4(ak, sk, "")
	return minio.New(u.Host, &minio.Options{Creds: creds, Secure: u.Scheme == "https", Region: v.Region})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code, t, p := s.serve(w, r)
	if p == "/health" && code == http.StatusOK {
		return
	}
	who := "-"
	if t != nil {
		who = fmt.Sprintf("sub=%q grp=%q jti=%q", t.Sub, t.Grp, t.Jti)
	}
	log.Printf("%s %s %q %d %s", r.RemoteAddr, r.Method, p, code, who)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) (code int, t *token.Token, p string) {
	fail := func(c int) (int, *token.Token, string) {
		if c == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		http.Error(w, http.StatusText(c), c)
		return c, t, p
	}
	// The path exactly as sent, never Go's decoded r.URL.Path (docs/TOKEN.md).
	p, _, _ = strings.Cut(r.RequestURI, "?")
	if p == "/health" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		fmt.Fprintln(w, "ok")
		return http.StatusOK, nil, p
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		return fail(http.StatusMethodNotAllowed)
	}
	segs, err := token.ParsePath(p)
	if err != nil {
		return fail(http.StatusBadRequest)
	}
	b, key := s.resolve(segs)
	now := s.now()
	expiry := s.urlLife
	if b == nil || !b.Public {
		// the token comes before 404, so no one learns the bindings without one
		tok := bearer(r)
		if tok == "" {
			return fail(http.StatusUnauthorized)
		}
		if t, err = s.verify(tok, now); err != nil {
			log.Printf("%s %s %q: %v", r.RemoteAddr, r.Method, p, err) // logged, never sent back
			return fail(http.StatusUnauthorized)
		}
		if b == nil {
			return fail(http.StatusNotFound)
		}
		if !t.Allows(r.Method, segs) {
			return fail(http.StatusForbidden)
		}
		if left := time.Unix(t.Exp, 0).Sub(now); left < expiry {
			expiry = max(left, minURLExpiry) // a URL never outlives its token
		}
	}
	loc, err := s.location(b.Volume, r.Method, key, expiry, r)
	if err != nil {
		log.Printf("presign %s: %v", key, err)
		return fail(http.StatusBadGateway)
	}
	w.Header().Set("Location", loc)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
	return http.StatusFound, t, p
}

// location is a presigned URL, or for an anonymous volume the plain path-style URL.
func (s *Server) location(volume, method, key string, expiry time.Duration, r *http.Request) (string, error) {
	vol := s.volumes[volume]
	if c := s.clients[volume]; c != nil {
		u, err := c.Presign(r.Context(), method, vol.Bucket, key, expiry, nil)
		if err != nil {
			return "", err
		}
		return u.String(), nil
	}
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		segs[i] = strings.ReplaceAll(url.PathEscape(seg), "+", "%2B") // S3 may read + as space
	}
	return strings.TrimSuffix(vol.Endpoint, "/") + "/" + url.PathEscape(vol.Bucket) + "/" + strings.Join(segs, "/"), nil
}

// resolve finds the binding with the longest prefix and the object key under it.
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
			rest := strings.Join(segs[len(b.segs):], "/")
			if b.KeyPrefix == "" {
				return b, rest
			}
			return b, b.KeyPrefix + "/" + rest
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
