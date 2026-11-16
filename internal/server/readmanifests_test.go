// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

func TestManifestsAreRead(t *testing.T) {
	s, _, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	x := withIndex(t, s)
	ctx := context.Background()
	bucket := s.place["s3"]
	m.objs["MM/release_x-1/a.el9.json"] = []byte(`{"build_id": "release_x-1", "packages": [{"hash": "aa", "effective_architecture": "el9"}]}`)
	m.objs["MM/common-manifest-el9.json"] = []byte(`{"kind": "common-manifest", "sources": ["release_x-1"], "packages": []}`)
	m.objs["MM/release_x-1/sbom.json"] = []byte(`{"packages": [` + strings.Repeat(" ", 100) + `]}`)
	m.objs["MM/release_x-1/NOTICE"] = []byte("notice")
	m.objs["MM/rev-index/el9/ROOT/6-1.json"] = []byte("aa")
	m.objs["PM/release_y-2/b.el9.json"] = []byte(`{"build_id": "release_y-2", "packages": []}`)
	maxManifest = 100 // the "SBOM" is too big to read
	t.Cleanup(func() { maxManifest = 16 << 20 })
	kind := func(key string) string {
		k, _, err := x.Builds(ctx, bucket, key)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	s.verifyDue(ctx, map[string]time.Time{})
	s.readManifests(ctx)
	for key, want := range map[string]string{"MM/release_x-1/a.el9.json": "bom", "MM/common-manifest-el9.json": "common",
		"MM/release_x-1/sbom.json": "none", "PM/release_y-2/b.el9.json": "bom", "MM/release_x-1/NOTICE": "",
		"MM/rev-index/el9/ROOT/6-1.json": ""} {
		if got := kind(key); got != want {
			t.Fatalf("%s: %q, want %q", key, got, want)
		}
	}
	if m.got != 3 {
		t.Fatalf("%d reads: the big one is not read", m.got)
	}
	if s.readManifests(ctx); m.got != 3 {
		t.Fatal("read again unchanged")
	}
	// changed outside: read again after the next listing; a failed read waits an hour
	m.objs["MM/release_x-1/a.el9.json"] = []byte(`{"build_id": "release_z-3", "packages": []}`)
	clock := now.Add(s.verifyEvery)
	s.now = func() time.Time { return clock }
	s.verifyDue(ctx, map[string]time.Time{})
	m.getFails = true
	if s.readManifests(ctx); kind("MM/release_x-1/a.el9.json") != "unread" {
		t.Fatal("a failed read not noted")
	}
	m.getFails = false
	got := m.got
	clock = clock.Add(index.RetryUnread - time.Second)
	if s.readManifests(ctx); m.got != got {
		t.Fatal("tried again within the hour")
	}
	clock = clock.Add(time.Second)
	s.readManifests(ctx)
	if _, builds, _ := x.Builds(ctx, bucket, "MM/release_x-1/a.el9.json"); !slices.Equal(builds, []string{"release_z-3"}) {
		t.Fatalf("not read again: %v", builds)
	}
	// gone since the listing (404): unread, as it may come back with its ETag
	m.objs["MM/release_x-1/gone.json"] = []byte(`{}`)
	clock = clock.Add(s.verifyEvery)
	s.verifyDue(ctx, map[string]time.Time{})
	delete(m.objs, "MM/release_x-1/gone.json")
	if s.readManifests(ctx); kind("MM/release_x-1/gone.json") != "unread" {
		t.Fatal("a file gone not noted")
	}
	// a store that fails: one try a tick, not one per file
	m.objs["MM/f1/a.json"], m.objs["MM/f2/a.json"] = []byte(`{}`), []byte(`{}`)
	clock = clock.Add(s.verifyEvery)
	s.verifyDue(ctx, map[string]time.Time{})
	m.getFails, got = true, m.got
	if s.readManifests(ctx); m.got != got+1 || kind("MM/f2/a.json") != "" {
		t.Fatalf("%d reads of a failing store", m.got-got)
	}
	m.getFails = false
	for _, k := range []string{"MM/f1/a.json", "MM/f2/a.json", "MM/release_x-1/gone.json"} {
		delete(m.objs, k) // gone before the next listing: their rows go
	}
	// one tick reads at most manifestsPerTick
	manifestsPerTick = 1
	t.Cleanup(func() { manifestsPerTick = 500 })
	m.objs["MM/n1/a.json"], m.objs["MM/n2/a.json"], m.objs["PM/n3/a.json"] = []byte(`{}`), []byte(`{}`), []byte(`{}`)
	clock = clock.Add(s.verifyEvery)
	s.verifyDue(ctx, map[string]time.Time{})
	if s.readManifests(ctx); kind("MM/n1/a.json") != "none" || kind("MM/n2/a.json") != "" || kind("PM/n3/a.json") != "" {
		t.Fatal("not one a tick")
	}
}
