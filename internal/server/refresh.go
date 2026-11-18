// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

var (
	errPanicked = errors.New("the computation panicked")
	errNoAnswer = errors.New("no answer")
)

const (
	refreshTime  = 10 * time.Minute // the longest one computation may take
	refreshStale = 2                // an answer older than this many intervals is not given
)

var refreshWait = 5 * time.Second // how long a request with an older answer waits for a newer one

// refreshed is a value computed from the index at most once an interval, one
// computation at a time and not bound to the request that started it: a scraper
// that gives up before it ends still leaves its answer for the next. A request
// waits for a newer answer up to refreshWait, then takes the last one; with none
// (or one too old), it waits as long as its own context allows. A computation that
// failed is the error of the requests that waited for it, not a last answer.
type refreshed[T any] struct {
	mu      sync.Mutex
	at      time.Time // when the last answer's computation began
	val     T
	have    bool
	running chan struct{} // closed when the computation in flight ends; nil: none
	err     error         // the last computation's, when it gave no answer
}

// get is the newest answer, computed again when now is an interval past the last;
// compute gets a context of its own, ending after refreshTime.
func (c *refreshed[T]) get(ctx context.Context, now time.Time, every time.Duration,
	clock func() time.Time, compute func(context.Context) (T, error)) (T, error) {
	var zero T
	c.mu.Lock()
	if due := !c.have || now.Sub(c.at) >= every || now.Before(c.at); due && c.running == nil {
		done := make(chan struct{})
		c.running = done
		go func(start time.Time) {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTime)
			var v T
			err := errPanicked
			func() {
				defer func() {
					if p := recover(); p != nil { // as net/http would: the service goes on
						log.Printf("panic computing an answer: %v\n%s", p, debug.Stack())
					}
				}()
				v, err = compute(cctx)
			}()
			cancel()
			c.mu.Lock()
			if err == nil {
				c.at, c.val, c.have = start, v, true
			}
			c.err, c.running = err, nil
			c.mu.Unlock()
			close(done)
		}(clock())
	}
	usable := func() bool { // under c.mu
		return c.have && now.Sub(c.at) < time.Duration(refreshStale)*every && !now.Before(c.at)
	}
	wait, fallback := c.running, usable()
	c.mu.Unlock()
	ended := false
	if wait != nil {
		var timeout <-chan time.Time
		if fallback {
			t := time.NewTimer(refreshWait)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case <-wait:
			ended = true
		case <-timeout: // the last answer, the newer one still computed
		case <-ctx.Done():
			if !fallback {
				return zero, ctx.Err()
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case ended && c.err != nil:
		return zero, c.err
	case ended || fallback: // the computation waited for, or the last answer
		return c.val, nil
	}
	return zero, errNoAnswer // not reached: one is computing, or there is an answer
}
