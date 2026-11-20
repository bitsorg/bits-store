// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/format"
	"github.com/bitsorg/bits-store/internal/token"
)

// A crates binding (README): cargo's registry of the site, a read-through mirror of a
// sparse index (crates.io's unless index names another). Its config.json points
// downloads here; a crate is fetched into the store on its first read, checked
// against the checksum its index lists, and sent to the registry meanwhile.
const (
	cratesIndex        = "https://index.crates.io"
	crateIndexTTL      = 5 * time.Minute // an index file is asked again after this
	maxCrateIndexFiles = 20000           // index files kept
	maxCrateIndexBytes = 16 << 20
)

type crateIndexFile struct {
	at   time.Time
	body []byte
}

// crateIndexCache keeps the index's files: a fresh one for crateIndexTTL, an older
// one when the index cannot answer. A reload shares it.
type crateIndexCache struct {
	mu sync.Mutex
	m  map[string]*crateIndexFile
}

// file is the index's file at path (config.json, or a crate's), errNoProject when
// it has none.
func (c *crateIndexCache) file(ctx context.Context, client *http.Client, index, path string, now time.Time) ([]byte, error) {
	k := index + "\x00" + path
	c.mu.Lock()
	old := c.m[k]
	c.mu.Unlock()
	if old != nil && now.Sub(old.at) < crateIndexTTL && !now.Before(old.at) {
		return old.body, nil
	}
	body, err := fetchCrateIndex(ctx, client, strings.TrimSuffix(index, "/")+"/"+path)
	switch {
	case err == nil:
		c.mu.Lock()
		if c.m == nil || len(c.m) >= maxCrateIndexFiles {
			c.m = map[string]*crateIndexFile{}
		}
		c.m[k] = &crateIndexFile{now, body}
		c.mu.Unlock()
		return body, nil
	case old != nil && !errors.Is(err, errNoProject):
		return old.body, nil // the index down: the file as it was
	}
	return nil, err
}

func fetchCrateIndex(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, pageTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bits-store")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, errNoProject
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the index answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCrateIndexBytes+1))
	if err == nil && len(body) > maxCrateIndexBytes {
		err = errors.New("the index's file is too large")
	}
	return body, err
}

// serveCrates answers a crates binding's read: its config.json, an index file, or a
// crate, from the store or, the first time, from the registry while it is fetched.
func (s *Server) serveCrates(w http.ResponseWriter, r *http.Request, b *Binding, key string, t *token.Token, now time.Time) int {
	k := b.unprefixed(key)
	switch {
	case k == "index/config.json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"dl": strings.TrimSuffix(b.URL, "/") + "/crates"})
		return http.StatusOK
	case strings.HasPrefix(k, "index/"):
		body, err := s.crateIndex.file(r.Context(), s.fetchClient, b.index(), strings.TrimPrefix(k, "index/"), now)
		switch {
		case errors.Is(err, errNoProject):
			return fail(w, http.StatusNotFound)
		case err != nil:
			s.errorf("crates_index_failed", k, "crates index %s: %v", k, err)
			return fail(w, http.StatusBadGateway)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(body)
		return http.StatusOK
	}
	if _, ok, err := s.stores[b.Volume].Stat(r.Context(), key); err != nil { // files/<crate>/<crate>-<version>.crate
		s.errorf("volume_request_failed", key, "stat %s: %v", key, err)
		return fail(w, http.StatusBadGateway)
	} else if ok {
		return s.redirect(w, r, b, key, t, now)
	}
	parts := strings.Split(k, "/")
	name := parts[1]
	version := strings.TrimSuffix(strings.TrimPrefix(parts[2], name+"-"), ".crate")
	sum, src, err := s.crateOrigin(r.Context(), b, name, version, now)
	switch {
	case errors.Is(err, errNoProject):
		return fail(w, http.StatusNotFound)
	case err != nil:
		s.errorf("crates_index_failed", name, "crates index for %s %s: %v", name, version, err)
		return fail(w, http.StatusBadGateway)
	}
	s.pypiFetch(b, key, pyFile{Name: parts[2], URL: src, SHA256: sum}, t, now)
	w.Header().Set("Location", src)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
	return http.StatusFound
}

// crateOrigin is a crate's SHA-256, from its index file, and where the registry has
// it (its config.json's dl); errNoProject when the index lists no such version.
func (s *Server) crateOrigin(ctx context.Context, b *Binding, name, version string, now time.Time) (sum, src string, err error) {
	body, err := s.crateIndex.file(ctx, s.fetchClient, b.index(), format.CrateIndexPath(strings.ToLower(name)), now)
	if err != nil {
		return "", "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), maxCrateIndexBytes)
	for sc.Scan() {
		var v struct{ Name, Vers, Cksum string }
		if json.Unmarshal(sc.Bytes(), &v) == nil && v.Name == name && v.Vers == version && sha256Hex.MatchString(v.Cksum) {
			sum = v.Cksum
		}
	}
	if sum == "" {
		return "", "", errNoProject
	}
	conf, err := s.crateIndex.file(ctx, s.fetchClient, b.index(), "config.json", now)
	if err != nil {
		return "", "", err
	}
	var c struct{ Dl string }
	scheme, _, _ := strings.Cut(b.index(), "://")
	if json.Unmarshal(conf, &c) != nil || !strings.HasPrefix(c.Dl, "https://") && !strings.HasPrefix(c.Dl, scheme+"://") {
		return "", "", errors.New("the index's config.json names no download by https (or as the index)")
	}
	if !strings.ContainsAny(c.Dl, "{") {
		return sum, strings.TrimSuffix(c.Dl, "/") + "/" + name + "/" + version + "/download", nil
	}
	lower := strings.ToLower(name)
	return sum, strings.NewReplacer("{crate}", name, "{version}", version, "{sha256-checksum}", sum,
		"{prefix}", strings.TrimSuffix(format.CrateIndexPath(name), "/"+name),
		"{lowerprefix}", strings.TrimSuffix(format.CrateIndexPath(lower), "/"+lower)).Replace(c.Dl), nil
}
