// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A computation outlives the request that gave up on it; a newer answer is waited
// for a while, else the last one given; one computation at a time; a failure is the
// error of those who waited for it.
func TestRefreshed(t *testing.T) {
	defer func(w time.Duration) { refreshWait = w }(refreshWait)
	refreshWait = 50 * time.Millisecond
	var c refreshed[int]
	var runs atomic.Int32
	release := make(chan struct{})
	result := func() (int, error) { return int(runs.Load()), nil }
	compute := func(ctx context.Context) (int, error) {
		runs.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		return result()
	}
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	get := func(ctx context.Context) (int, error) { return c.get(ctx, now, time.Minute, clock, compute) }

	gone, cancel := context.WithCancel(context.Background()) // the scraper gives up
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := get(gone); !errors.Is(err, context.Canceled) {
		t.Fatalf("no answer yet, the request gone: %v", err)
	}
	release <- struct{}{} // its computation goes on, and ends
	waitFor(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.have })
	if v, err := get(context.Background()); v != 1 || err != nil || runs.Load() != 1 {
		t.Fatalf("the answer it left: %d %v (%d runs)", v, err, runs.Load())
	}

	now = now.Add(time.Minute) // due: concurrent requests, one computation, the last answer
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := get(context.Background()); v != 1 || err != nil {
				t.Errorf("the last answer while one computes: %d %v", v, err)
			}
		}()
	}
	wg.Wait()
	if runs.Load() != 2 {
		t.Fatalf("one computation at a time: %d", runs.Load())
	}
	release <- struct{}{}
	waitFor(t, func() bool { v, _ := get(context.Background()); return v == 2 })

	now = now.Add(time.Minute) // a failure: an error for those who waited, not the last answer
	result = func() (int, error) { return 0, errors.New("index closed") }
	go func() { time.Sleep(10 * time.Millisecond); release <- struct{}{} }()
	if _, err := c.get(context.Background(), now, time.Minute, clock, compute); err == nil {
		t.Fatal("a failed computation gave the last answer")
	}

	now = now.Add(11 * time.Minute) // too old to give: wait for the next
	result = func() (int, error) { return 7, nil }
	go func() { time.Sleep(100 * time.Millisecond); release <- struct{}{} }()
	if v, err := get(context.Background()); v != 7 || err != nil {
		t.Fatalf("an answer too old was given: %d %v", v, err)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 200 {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("not in time")
}

// On a real clock (the computation starts a moment after the request's now), the
// request that waited gets that computation's answer, never an empty one.
func TestRefreshedOnARealClock(t *testing.T) {
	var c refreshed[string]
	for i := range 3 {
		v, err := c.get(context.Background(), time.Now(), time.Nanosecond, time.Now,
			func(context.Context) (string, error) { return "answer", nil })
		if v != "answer" || err != nil {
			t.Fatalf("%d: %q %v", i, v, err)
		}
	}
}
