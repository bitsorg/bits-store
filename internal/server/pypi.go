// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/token"
)

// A pypi binding (README): pip reads a project's page here, made from the index's
// (PEP 691 JSON) with each file's link pointing back here; a file is fetched into
// the store on its first read, which is sent to the index meanwhile.
const (
	pypiIndex    = "https://pypi.org/simple"
	pypiJSON     = "application/vnd.pypi.simple.v1+json"
	pageTTL      = 10 * time.Minute // a page is asked of the index again after this
	maxPages     = 5000             // pages kept
	maxPageBytes = 64 << 20
	pageTimeout  = 30 * time.Second

	maxRoomWaiting = 1000 // files waiting for room to be fetched
)

var (
	roomWait = 10 * time.Minute // a file waits this long for room, then is not kept
	roomPoll = time.Second
)

var errNoProject = errors.New("no such project")

// pyFile is one file a page lists, with its SHA-256 (files without are left out).
type pyFile struct {
	Name, URL, SHA256 string
	RequiresPython    *string
	Yanked            json.RawMessage
}

type pyPage struct {
	at    time.Time
	files []pyFile
}

// pageCache keeps the index's pages: a fresh one for pageTTL, an older one when
// the index cannot answer. A reload shares it.
type pageCache struct {
	mu sync.Mutex
	m  map[string]*pyPage
}

func (c *pageCache) page(ctx context.Context, client *http.Client, index, project string, now time.Time) (*pyPage, error) {
	k := index + "\x00" + project
	c.mu.Lock()
	old := c.m[k]
	c.mu.Unlock()
	if old != nil && now.Sub(old.at) < pageTTL && !now.Before(old.at) {
		return old, nil
	}
	p, err := fetchPage(ctx, client, index, project, now)
	switch {
	case err == nil:
		c.mu.Lock()
		if c.m == nil || len(c.m) >= maxPages {
			c.m = map[string]*pyPage{}
		}
		c.m[k] = p
		c.mu.Unlock()
		return p, nil
	case old != nil && !errors.Is(err, errNoProject):
		log.Printf("pypi page %s: %v; the one of %s served", project, err, old.at.UTC().Format(time.RFC3339))
		return old, nil
	}
	return nil, err
}

func fetchPage(ctx context.Context, client *http.Client, index, project string, now time.Time) (*pyPage, error) {
	ctx, cancel := context.WithTimeout(ctx, pageTimeout)
	defer cancel()
	base := strings.TrimSuffix(index, "/") + "/" + project + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", pypiJSON)
	req.Header.Set("User-Agent", "bits-store")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errNoProject
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the index answered %d", resp.StatusCode)
	}
	var doc struct {
		Files []struct {
			Filename       string            `json:"filename"`
			URL            string            `json:"url"`
			Hashes         map[string]string `json:"hashes"`
			RequiresPython *string           `json:"requires-python"`
			Yanked         json.RawMessage   `json:"yanked"`
		} `json:"files"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPageBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("the index's page: %v", err)
	}
	u := resp.Request.URL // where the page was, after redirects: its links' base
	p := &pyPage{at: now}
	for _, f := range doc.Files {
		ref, err := url.Parse(f.URL)
		if err != nil || !sha256Hex.MatchString(f.Hashes["sha256"]) {
			continue
		}
		abs := u.ResolveReference(ref)
		if abs.Scheme != "https" && abs.Scheme != u.Scheme {
			continue // https, or as the index itself
		}
		abs.Fragment = ""
		p.files = append(p.files, pyFile{f.Filename, abs.String(), f.Hashes["sha256"], f.RequiresPython, f.Yanked})
	}
	return p, nil
}

// servePyPI answers a pypi binding's read: a project's page, or a file, from the
// store or, the first time, from the index while it is fetched into the store.
func (s *Server) servePyPI(w http.ResponseWriter, r *http.Request, b *Binding, key string, t *token.Token, now time.Time) int {
	parts := strings.Split(b.unprefixed(key), "/") // simple/<project> or files/<project>/<sha256>/<file>
	if parts[0] == "simple" && !strings.Contains(r.Header.Get("Accept"), pypiJSON) {
		return failMsg(w, http.StatusNotAcceptable, "accept "+pypiJSON)
	}
	if parts[0] == "files" {
		if _, ok, err := s.stores[b.Volume].Stat(r.Context(), key); err != nil {
			log.Printf("stat %s: %v", key, err)
			return fail(w, http.StatusBadGateway)
		} else if ok {
			return s.redirect(w, r, b, key, t, now)
		}
	}
	page, err := s.pages.page(r.Context(), s.fetchClient, b.index(), parts[1], now)
	switch {
	case errors.Is(err, errNoProject):
		return fail(w, http.StatusNotFound)
	case err != nil:
		log.Printf("pypi page %s: %v", parts[1], err)
		return fail(w, http.StatusBadGateway)
	case parts[0] == "simple":
		return s.pypiPage(w, b, parts[1], page)
	}
	for _, f := range page.files {
		if f.SHA256 == parts[2] && f.Name == parts[3] {
			s.pypiFetch(b, key, f, t, now)
			w.Header().Set("Location", f.URL)
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusFound)
			return http.StatusFound
		}
	}
	return fail(w, http.StatusNotFound) // not on the index's page, nor in the store
}

func (s *Server) pypiPage(w http.ResponseWriter, b *Binding, project string, page *pyPage) int {
	type file struct {
		Filename       string            `json:"filename"`
		URL            string            `json:"url"`
		Hashes         map[string]string `json:"hashes"`
		RequiresPython *string           `json:"requires-python,omitempty"`
		Yanked         json.RawMessage   `json:"yanked,omitempty"`
	}
	files := make([]file, 0, len(page.files))
	for _, f := range page.files {
		link := b.Prefix + "/files/" + project + "/" + f.SHA256 + "/" + f.Name
		if segs, err := token.ParsePath(link); err != nil {
			continue // a name the store cannot hold: left out
		} else if rb, k, _ := s.resolve(segs); rb != b || k == "" {
			continue
		}
		files = append(files, file{f.Name, link,
			map[string]string{"sha256": f.SHA256}, f.RequiresPython, f.Yanked})
	}
	w.Header().Set("Content-Type", pypiJSON)
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"meta": map[string]string{"api-version": "1.0"}, "name": project, "files": files})
	return http.StatusOK
}

// pypiFetch fetches f into the store at key in the background, once, as a sources
// fetch is; with no room it waits for some, as pip reads a project's files in a
// burst (throttled, beyond the budget: not kept, make its host trusted).
func (s *Server) pypiFetch(b *Binding, key string, f pyFile, t *token.Token, now time.Time) {
	host := strings.ToLower(strings.TrimSuffix(urlHost(f.URL), "."))
	var budget *fetchPolicy
	if !s.policy.isTrusted(host) {
		budget = s.policy
	}
	k := s.place[b.Volume] + "\x00" + key
	job, fresh, err := s.fetches.join(k, t.Sub, domainOf(host), budget, now)
	if errors.Is(err, errFull) && s.fetches.waiting.Add(1) > maxRoomWaiting {
		s.fetches.waiting.Add(-1) // too many waiting already: not kept this time
	} else if errors.Is(err, errFull) {
		go func() {
			defer s.fetches.waiting.Add(-1)
			for end := time.Now().Add(roomWait); errors.Is(err, errFull) && time.Now().Before(end); {
				time.Sleep(roomPoll)
				job, fresh, err = s.fetches.join(k, t.Sub, domainOf(host), budget, s.now())
			}
			s.pypiFetchJob(b, key, f, t.Sub, k, job, fresh, err)
		}()
		return
	}
	go s.pypiFetchJob(b, key, f, t.Sub, k, job, fresh, err)
}

// pypiFetchJob runs a fetch join gave: a fresh one, not one running already.
func (s *Server) pypiFetchJob(b *Binding, key string, f pyFile, sub, k string, job *fetchJob, fresh bool, err error) {
	if err != nil {
		log.Printf("fetch %s from %s: %v", key, f.URL, err)
		return
	} else if !fresh {
		return
	}
	n, err := s.fetch(b.Volume, b.MaxSize, key, f.URL, sub, f.SHA256)
	if err != nil {
		log.Printf("fetch %s from %s failed after %d bytes: %v", key, f.URL, n, err)
	} else {
		log.Printf("fetched %s from %s: %d bytes", key, f.URL, n)
	}
	s.fetches.finish(k, job, err, s.now())
}

// index is the index a pypi binding mirrors.
func (b *Binding) index() string {
	if b.Index != "" {
		return b.Index
	}
	return pypiIndex
}
