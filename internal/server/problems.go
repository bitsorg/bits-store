// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// Problems: the service's warnings and errors, logged as before and kept in the
// index (30 days), for the admin API (GET /_admin/problems), whose reader (the
// console backend) makes issues of them as of failed builds.
const (
	levelWarning   = "warning"
	levelError     = "error"
	maxProblemKeys = 1000 // different problems between two writes to the index; others only logged
	maxProblemText = 1024 // a message's bytes kept
	maxProblemList = 1000 // problems in one answer of the admin API
)

// problemTable gathers problems until they are written to the index, the same
// one counted once with how many times it was seen.
type problemTable struct {
	mu sync.Mutex
	m  map[[4]string]*index.Problem // level, kind, subject, message
}

// problem logs a warning or an error, and records it for the index: kind names what
// failed (a stable name), subject what it failed on (a key, a volume, a repository).
func (s *Server) problem(level, kind, subject, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	s.record(level, kind, subject, msg)
}

// record keeps a problem for the index without logging it (logged otherwise).
func (s *Server) record(level, kind, subject, msg string) {
	if s.index == nil || s.problems == nil {
		return
	}
	if len(msg) > maxProblemText {
		msg = msg[:maxProblemText]
	}
	now := s.now()
	k := [4]string{level, kind, subject, msg}
	pt := s.problems
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.m == nil {
		pt.m = map[[4]string]*index.Problem{}
	}
	if p := pt.m[k]; p != nil {
		p.Count++
		p.Last = now
	} else if len(pt.m) < maxProblemKeys {
		pt.m[k] = &index.Problem{First: now, Last: now, Count: 1, Level: level, Kind: kind, Subject: subject, Message: msg}
	}
}

func (s *Server) warnf(kind, subject, format string, args ...any) {
	s.problem(levelWarning, kind, subject, format, args...)
}

func (s *Server) errorf(kind, subject, format string, args ...any) {
	s.problem(levelError, kind, subject, format, args...)
}

// flushProblems writes the problems gathered since the last call to the index.
func (s *Server) flushProblems(ctx context.Context) {
	if s.index == nil || s.problems == nil {
		return
	}
	s.problems.mu.Lock()
	m := s.problems.m
	s.problems.m = nil
	s.problems.mu.Unlock()
	if len(m) == 0 {
		return
	}
	ps := make([]index.Problem, 0, len(m))
	for _, p := range m {
		ps = append(ps, *p)
	}
	if err := s.index.AddProblems(ctx, ps, s.now()); err != nil {
		log.Printf("index: %d problems not kept: %v", len(ps), err)
	}
}

// adminProblems answers GET /_admin/problems?since=<ms>&limit=<n>: the problems last
// seen at or after since, oldest first; a reader asks again from the last one's.
func (s *Server) adminProblems(w http.ResponseWriter, r *http.Request, rawQuery string) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return fail(w, http.StatusBadRequest)
	}
	since, limit := int64(0), maxProblemList
	if v := q.Get("since"); v != "" {
		if since, err = strconv.ParseInt(v, 10, 64); err != nil || since < 0 {
			return fail(w, http.StatusBadRequest)
		}
	}
	if v := q.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > maxProblemList {
			return fail(w, http.StatusBadRequest)
		}
	}
	ps, err := s.index.Problems(r.Context(), since, limit)
	if err != nil {
		log.Printf("admin problems: %v", err)
		return fail(w, http.StatusInternalServerError)
	}
	return writeJSON(w, map[string]any{"problems": ps, "kept_days": int(index.ProblemsKept / (24 * time.Hour))})
}
