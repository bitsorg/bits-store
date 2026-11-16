// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// The GETs the service redirects are counted per object, written to the index by
// the verifier's tick; HEADs, refusals and objects not indexed are not.
func TestReadsCounted(t *testing.T) {
	s, good, now := setup(t)
	x := withIndex(t, s)
	ctx := context.Background()
	auth := map[string]string{"Authorization": "Bearer " + good}
	bucket := s.place["s3"]
	x.Put(ctx, bucket, index.Object{Key: finalKey, Size: 1, ETag: "e"}, now)
	get := func(method string, hdr map[string]string) int { return do(s, method, final, hdr).Code }
	if get("GET", auth) != 302 || get("GET", auth) != 302 || get("HEAD", auth) != 302 || get("GET", nil) != 401 {
		t.Fatal("not served as before")
	}
	do(s, "GET", "/sources/archives/not-indexed", auth)
	s.flushReads(ctx)
	read := func() index.Object {
		var got index.Object
		x.Each(ctx, bucket, "TARS", func(o index.Object) {
			if o.Key == finalKey {
				got = o
			}
		})
		return got
	}
	if o := read(); o.Reads != 2 || !o.ReadAt.Equal(now) {
		t.Fatalf("%d reads, the last %v", o.Reads, o.ReadAt)
	}
	later := now.Add(time.Hour)
	s.now = func() time.Time { return later }
	get("GET", auth)
	s.flushReads(ctx)
	if o := read(); o.Reads != 3 || !o.ReadAt.Equal(later) {
		t.Fatalf("%d reads, the last %v", o.Reads, o.ReadAt)
	}
	s.flushReads(ctx) // nothing new: nothing added
	if o := read(); o.Reads != 3 {
		t.Fatal("counted twice")
	}
}

func TestReadsWithoutAnIndex(t *testing.T) {
	s, good, _ := setup(t)
	if c := do(s, "GET", final, map[string]string{"Authorization": "Bearer " + good}).Code; c != 302 || s.reads.m != nil {
		t.Fatalf("%d; counted without an index", c)
	}
}

func TestReadsBounded(t *testing.T) {
	rt := &readTable{}
	now := time.Now()
	for i := range maxReadKeys + 5 {
		rt.add("b", "k"+strconv.Itoa(i), now)
	}
	rt.add("b", "k0", now) // one counted already: still counted
	m, dropped := rt.take()
	if len(m) != maxReadKeys || dropped != 5 || m[[2]string{"b", "k0"}].N != 2 {
		t.Fatalf("%d objects, %d dropped, k0 %+v", len(m), dropped, m[[2]string{"b", "k0"}])
	}
	if m, dropped := rt.take(); m != nil || dropped != 0 {
		t.Fatal("not emptied")
	}
}
