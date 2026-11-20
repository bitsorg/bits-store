// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

func withIndex(t *testing.T, s *Server) *index.Index {
	x, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	s.index = x
	return x
}

func indexed(t *testing.T, s *Server, volume, key string) (index.Object, bool) {
	o, ok, err := s.index.Get(context.Background(), s.place[volume], key)
	if err != nil {
		t.Fatal(err)
	}
	return o, ok
}

func TestAPromoteIsIndexed(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	withIndex(t, s)
	data := []byte("package tarball")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d", w.Code)
	}
	sum := sha256.Sum256(data)
	o, ok := indexed(t, s, "s3", finalKey)
	if !ok || o.Size != int64(len(data)) || o.ETag != m.etag(finalKey) || o.SHA256 != hex.EncodeToString(sum[:]) ||
		o.Grp != "lhcb" || m.meta[finalKey]["bits-group"] != "lhcb" || o.Origin != index.OriginUpload || o.Sub == "" ||
		m.meta[finalKey]["bits-by"] == "" {
		t.Fatalf("not indexed as promoted, with its writer's group and subject: %+v %v %v", o, ok, m.meta[finalKey])
	}
	// changed outside the service: its writer is not known any more
	m.objs[finalKey] = []byte("other bytes")
	now := s.now()
	s.now = func() time.Time { return now.Add(s.verifyEvery) }
	s.verifyDue(context.Background(), map[string]time.Time{})
	if o, _ := indexed(t, s, "s3", finalKey); o.Grp != "" || o.Origin != "" || o.Sub != "" {
		t.Fatalf("a changed object kept its writer: %+v", o)
	}
	if _, ok := indexed(t, s, "s3", "STAGING/"+st.ID); ok {
		t.Fatal("the staged object indexed")
	}
}

// The index takes an object's writer from the object: the same bytes from another
// group keep the first; a stale row (deleted outside the service) is replaced.
func TestTheWriterIsTheObjects(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	withIndex(t, s)
	data := []byte("package tarball")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.objs[finalKey], m.meta[finalKey] = data, map[string]string{"bits-group": "at%2Flas", "fetched-by": "job%2F7"} // came first
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d", w.Code)
	}
	if o, _ := indexed(t, s, "s3", finalKey); o.Grp != "at/las" || m.meta[finalKey]["bits-group"] != "at%2Flas" ||
		o.Origin != index.OriginFill || o.Sub != "job/7" {
		t.Fatalf("the first writer not kept: %+v", o)
	}
	delete(m.objs, finalKey)
	st = start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d", w.Code)
	}
	if o, _ := indexed(t, s, "s3", finalKey); o.Grp != "lhcb" {
		t.Fatalf("a stale row's writer kept: %+v", o)
	}
}

func TestWriter(t *testing.T) {
	for meta, want := range map[string]string{"lhcb": "lhcb", "a%2Fb": "a/b", "%zz": "", "": ""} {
		if g := writer(objInfo{Meta: map[string]string{"bits-group": meta}}); g != want {
			t.Fatalf("%q: %q", meta, g)
		}
	}
}

// The index is a cache: a promote it cannot record still succeeds, and is counted.
func TestAPromoteSucceedsWithoutTheIndex(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	withIndex(t, s).Close()
	data := []byte("package tarball")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 || !m.has(finalKey) {
		t.Fatalf("complete: %d", w.Code)
	}
	if s.index.Errors() != 1 {
		t.Fatalf("index errors: %d", s.index.Errors())
	}
}

func TestVerifyDue(t *testing.T) {
	s, _, now := setup(t)
	m := newMem()
	s.stores = map[string]objectStore{"s3": m, "s3-again": m, "pub": plainStore{}}
	s.place = map[string]string{"s3": "e bits", "s3-again": "e bits", "pub": "e open"}
	x := withIndex(t, s)
	m.objs["TARS/a/store/ab/abc/x-1-1.a.tar.gz"] = []byte("xx")
	m.objs[stagingPrefix+"/an-upload"] = []byte("x")
	clock := now
	s.now = func() time.Time { return clock }
	failed := map[string]time.Time{}
	s.verifyDue(context.Background(), failed)
	if _, ok := indexed(t, s, "s3", "TARS/a/store/ab/abc/x-1-1.a.tar.gz"); !ok || m.walked != 1 {
		t.Fatalf("the first verify: indexed %v, %d listings (one bucket under two names)", ok, m.walked)
	}
	at, d, ok, _ := x.Verified(context.Background(), "e bits")
	if _, staged := indexed(t, s, "s3", stagingPrefix+"/an-upload"); staged || d.Missing != 1 {
		t.Fatal("a staged upload indexed")
	}
	if !ok || !at.Equal(clock) || d.Missing != 1 {
		t.Fatalf("verified %v %+v %v", at, d, ok)
	}
	if _, _, ok, _ := x.Verified(context.Background(), "e open"); ok {
		t.Fatal("an anonymous volume listed")
	}
	// not due again before index_verify; then due
	clock = clock.Add(s.verifyEvery - time.Minute)
	if s.verifyDue(context.Background(), failed); m.walked != 1 {
		t.Fatal("listed again before index_verify")
	}
	clock = clock.Add(time.Minute)
	if s.verifyDue(context.Background(), failed); m.walked != 2 {
		t.Fatal("not listed at index_verify")
	}
}

func TestAFailedVerifyWaits(t *testing.T) {
	s, _, now := setup(t)
	m := newMem()
	s.stores = map[string]objectStore{"s3": m}
	s.place = map[string]string{"s3": "e bits"}
	x := withIndex(t, s)
	m.objs["a"], m.objs["b"] = []byte("a"), []byte("b")
	m.listFails = true
	clock := now
	s.now = func() time.Time { return clock }
	failed := map[string]time.Time{}
	s.verifyDue(context.Background(), failed)
	if _, ok := failed["e bits"]; !ok {
		t.Fatal("a failed listing not remembered")
	}
	m.listFails = false
	clock = clock.Add(verifyRetry - time.Second)
	s.verifyDue(context.Background(), failed)
	if _, _, ok, _ := x.Verified(context.Background(), "e bits"); ok {
		t.Fatal("listed again before verifyRetry")
	}
	clock = clock.Add(time.Second)
	s.verifyDue(context.Background(), failed)
	if _, _, ok, _ := x.Verified(context.Background(), "e bits"); !ok || len(failed) != 0 {
		t.Fatal("not listed again after verifyRetry")
	}
}

func TestIndexVerifyConfig(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/tokens/vectors.json")
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for every, ok := range map[string]bool{"": true, "1h": true, "59m": false, "x": false} {
		c := &Config{Issuer: v.Issuer, Audience: v.Audience, Keys: v.Keys, IndexVerify: every,
			Volumes:  map[string]VolumeConf{"pub": {Endpoint: "https://s3.example.org", Bucket: "open", Region: "us-east-1"}},
			Bindings: []Binding{{Prefix: "/public", Volume: "pub", Public: true}}}
		if _, err := New(c); (err == nil) != ok || err != nil && !strings.Contains(err.Error(), "index_verify") {
			t.Fatalf("index_verify %q: %v", every, err)
		}
	}
}

func indexObject(key string, size int64) index.Object {
	return index.Object{Key: key, Size: size, ETag: "e"}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
