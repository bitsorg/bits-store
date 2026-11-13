// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const revPath = "/store/lhcb/x86_64-el10-gcc14-opt/m/rev-index/x86_64-el9/zlib/v1.3"

func TestRevisions(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	dir := "MM/rev-index/x86_64-el9/zlib/"
	m.upload(dir+"v1.3-1", []byte(a+"\n"))
	m.upload(dir+"v1.3-local1", []byte(b))
	m.upload(dir+"v1.3-alice2-3", []byte(a)) // another version's
	m.upload(dir+"v1.3-4", []byte("not a hash"))
	m.upload(dir+"v1.3-5/x", []byte(a)) // not in the folder
	m.upload("MM/rev-index/x86_64-el8/zlib/v1.3-6", []byte(a))
	read := func(auth map[string]string) map[string]string {
		w := do(s, "GET", revPath+"?revisions", auth)
		var got map[string]string
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
			t.Fatalf("revisions: %d %s", w.Code, w.Body)
		}
		return got
	}
	if got := read(nil); len(got) != 2 || got["1"] != a || got["local1"] != b {
		t.Fatalf("anonymous: %v", got)
	}
	m.getFails = true // markers are written once: read again from what was read
	if got := read(nil); len(got) != 2 {
		t.Fatalf("again: %v", got)
	}
	m.getFails = false
	// a marker is written once, through the usual upload
	st := start(t, s, revPath+"-2", tok, []byte(b))
	m.upload("STAGING/"+st.ID, []byte(b))
	if w := post(s, revPath+"-2?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("marker: %d", w.Code)
	}
	if w := post(s, revPath+"-2?uploads", tok, body([]byte(a))); w.Code != 409 {
		t.Fatalf("a taken revision: %d", w.Code)
	}
	if got := read(map[string]string{"Authorization": "Bearer " + tok}); got["2"] != b || len(got) != 3 {
		t.Fatalf("after the marker: %v", got)
	}
	if w := do(s, "GET", "/store/lhcb/x86_64-el10-gcc14-opt/m/rev-index/x86_64-el9/zlib?revisions", nil); w.Code != 404 {
		t.Fatalf("not a version: %d", w.Code)
	}
	m.listFails = true
	if w := do(s, "GET", revPath+"?revisions", nil); w.Code != 502 {
		t.Fatalf("list fails: %d", w.Code)
	}
	m.listFails = false
	// the common manifests themselves, as files
	m.upload("MM/common-manifest-x86_64-el9.json", []byte("{}"))
	w := do(s, "GET", "/store/lhcb/x86_64-el10-gcc14-opt/m/common-manifest-x86_64-el9.json", nil)
	if w.Code != 302 || w.Header().Get("Location") != "https://s3.example.org/bits/MM/common-manifest-x86_64-el9.json" {
		t.Fatalf("a manifest: %d %v", w.Code, w.Header())
	}
}

func TestRevisionsRefusals(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	dir := "MM/rev-index/x86_64-el9/zlib/"
	m.upload(dir+"v1.3-1", []byte(""))
	m.upload(dir+"v1.3-2", []byte(strings.Repeat("a", 300)))
	m.upload(dir+"v1.3-3", []byte(strings.Repeat("A", 40)))
	m.upload(dir+"v1.3-4", []byte(strings.Repeat("c", 64)))
	for _, q := range []string{"?revisions", "?revisions="} {
		w := do(s, "GET", revPath+q, nil)
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"4":"`+strings.Repeat("c", 64)+`"}` {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
	}
	if w := do(s, "HEAD", revPath+"?revisions", nil); w.Code != 200 {
		t.Fatalf("HEAD: %d", w.Code)
	}
	private := strings.Replace(revPath, "/m/", "/pm/", 1)
	if w := do(s, "GET", private+"?revisions", nil); w.Code != 401 {
		t.Fatalf("a private binding without a token: %d", w.Code)
	}
	if w := do(s, "GET", private+"?revisions", map[string]string{"Authorization": "Bearer " + tok}); w.Code != 200 {
		t.Fatalf("a private binding with a token: %d", w.Code)
	}
	m.upload(dir+"v1.3-5", []byte(strings.Repeat("d", 40)))
	m.getFails = true
	if w := do(s, "GET", revPath+"?revisions", nil); w.Code != 502 {
		t.Fatalf("get fails: %d", w.Code)
	}
	m.getFails = false
	for i := range maxListed {
		m.upload(fmt.Sprintf("%sv1.3-%d", dir, 100+i), []byte(strings.Repeat("e", 40)))
	}
	if w := do(s, "GET", revPath+"?revisions", nil); w.Code != 502 {
		t.Fatalf("too many: %d", w.Code)
	}
	// a public binding with keys still takes writes only within the token
	if w := post(s, "/pubsrc/x?uploads", tok, body([]byte("x"))); w.Code != 403 {
		t.Fatalf("a write outside the token: %d", w.Code)
	}
}

// Two buckets with the same key prefix keep their own markers.
func TestRevisionsPerBucket(t *testing.T) {
	s, _, now := setup(t)
	a, b := newMem(), newMem()
	s.stores["s3"] = a
	key := "MM/rev-index/x86_64-el9/zlib/v1.3-1"
	a.upload(key, []byte(strings.Repeat("a", 40)))
	b.upload(key, []byte(strings.Repeat("b", 40)))
	do(s, "GET", revPath+"?revisions", nil)
	s.stores["s3"], s.place["s3"] = b, "https://s3.example.org other"
	w := do(s, "GET", revPath+"?revisions", nil)
	if !strings.Contains(w.Body.String(), strings.Repeat("b", 40)) {
		t.Fatalf("the other bucket's marker: %s", w.Body)
	}
	// and a marker rewritten by bits' own tools is read again after foundTTL
	b.upload(key, []byte(strings.Repeat("c", 40)))
	s.now = func() time.Time { return now.Add(foundTTL) }
	if w := do(s, "GET", revPath+"?revisions", nil); w.Code != 200 || !strings.Contains(w.Body.String(), strings.Repeat("c", 40)) {
		t.Fatalf("after foundTTL: %d %s", w.Code, w.Body)
	}
}
