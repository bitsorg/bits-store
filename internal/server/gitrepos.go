// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"cmp"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// GitRepo is a repository a git binding mirrors, as GET /_admin/git shows it.
type GitRepo struct {
	Binding   string     `json:"binding"`
	Repo      string     `json:"repo"`      // host/path, as clients name it
	Bytes     int64      `json:"bytes"`     // on -data
	Kept      int        `json:"kept"`      // checkouts kept for builds: refs/bits/*
	Refreshed *time.Time `json:"refreshed"` // its refs, last; null: not since the service started
}

// gitRepos walks the git bindings' repositories on -data, the largest first; what
// it found when ctx ends.
func (s *Server) gitRepos(ctx context.Context) []GitRepo {
	out := []GitRepo{}
	if s.git.root == "" {
		return out
	}
	for _, b := range s.bindings {
		if b.Format != "git" {
			continue
		}
		root := filepath.Join(s.git.root, filepath.FromSlash(b.KeyPrefix))
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if err != nil || !d.IsDir() || !strings.HasSuffix(d.Name(), ".git") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			r := GitRepo{Binding: b.Prefix, Repo: strings.TrimSuffix(filepath.ToSlash(rel), ".git"), Kept: keptRefs(p)}
			filepath.WalkDir(p, func(_ string, f fs.DirEntry, err error) error {
				if ctx.Err() != nil {
					return filepath.SkipAll
				}
				if err == nil && f.Type().IsRegular() {
					if i, err := f.Info(); err == nil {
						r.Bytes += i.Size()
					}
				}
				return nil
			})
			s.git.mu.Lock()
			if at, ok := s.git.refreshed[p]; ok {
				at = at.UTC()
				r.Refreshed = &at
			}
			s.git.mu.Unlock()
			out = append(out, r)
			return filepath.SkipDir
		})
	}
	slices.SortFunc(out, func(a, b GitRepo) int { return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), cmp.Compare(a.Repo, b.Repo)) })
	return out
}

// keptRefs counts a repository's refs/bits/*, loose or packed.
func keptRefs(dir string) int {
	n := 0
	filepath.WalkDir(filepath.Join(dir, "refs", "bits"), func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			n++
		}
		return nil
	})
	if f, err := os.Open(filepath.Join(dir, "packed-refs")); err == nil {
		defer f.Close()
		for sc := bufio.NewScanner(f); sc.Scan(); {
			if _, ref, ok := strings.Cut(sc.Text(), " "); ok && strings.HasPrefix(ref, "refs/bits/") {
				n++
			}
		}
	}
	return n
}
