// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

const maxReadKeys = 100000 // objects counted between two writes to the index; others lose theirs

// readTable counts the GETs the service redirects, by bucket and key, until the
// verifier adds them to the index (a request never waits on it).
type readTable struct {
	mu      sync.Mutex
	m       map[[2]string]index.Read
	dropped int64 // reads not counted: the table full
}

func (rt *readTable) add(bucket, key string, now time.Time) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	k := [2]string{bucket, key}
	r, ok := rt.m[k]
	if !ok && len(rt.m) >= maxReadKeys {
		rt.dropped++
		return
	}
	if rt.m == nil {
		rt.m = map[[2]string]index.Read{}
	}
	rt.m[k] = index.Read{N: r.N + 1, Last: now}
}

func (rt *readTable) take() (map[[2]string]index.Read, int64) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	m, dropped := rt.m, rt.dropped
	rt.m, rt.dropped = nil, 0
	return m, dropped
}

// flushReads adds the reads counted since the last call to the index.
func (s *Server) flushReads(ctx context.Context) {
	m, dropped := s.reads.take()
	if dropped > 0 {
		s.warnf("reads_dropped", "", "index: %d reads not counted: more than %d objects read in a minute", dropped, maxReadKeys)
	}
	if len(m) > 0 {
		if err := s.index.AddReads(ctx, m); err != nil {
			s.errorf("index_write_failed", "", "index: %d objects' reads lost: %v", len(m), err)
		}
	}
}

// FlushReads adds the reads counted, and the problems gathered, to the index every
// verifyTick, never waiting on a listing. It never returns.
func (r *Reloader) FlushReads() {
	for {
		time.Sleep(verifyTick)
		s := r.cur.Load()
		s.flushReads(context.Background())
		s.flushProblems(context.Background())
	}
}
