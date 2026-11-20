// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// cargo reads the registry's config.json here (its downloads here), a crate's
// index file from the index, and a crate from the registry the first time, while
// the store fetches it, checked against the index's checksum; then from the store.
func TestCrates(t *testing.T) {
	s, _, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	anyAddr(t)
	data, other := []byte("a crate"), []byte("not the crate the index lists")
	sum := sha256.Sum256(data)
	cksum := hex.EncodeToString(sum[:])
	var indexHits atomic.Int32
	var down atomic.Bool
	var reg *httptest.Server
	reg = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(503)
			return
		}
		switch r.URL.Path {
		case "/config.json":
			fmt.Fprintf(w, `{"dl": "%s/dl"}`, reg.URL)
		case "/it/oa/itoa":
			indexHits.Add(1)
			fmt.Fprintf(w, "{\"name\":\"itoa\",\"vers\":\"1.0.0\",\"cksum\":%q}\n{\"name\":\"itoa\",\"vers\":\"1.0.1\",\"cksum\":%q}\n",
				cksum, cksum)
		case "/dl/itoa/1.0.0/download":
			w.Write(data)
		case "/dl/itoa/1.0.1/download":
			w.Write(other)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(reg.Close)
	vol := VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bits", Region: "us-east-1", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
	conf := func(b Binding) error {
		_, err := (&Config{Volumes: map[string]VolumeConf{"s3": vol}, Bindings: []Binding{b}}).bindings()
		return err
	}
	if conf(Binding{Prefix: "/crates", Volume: "s3", KeyPrefix: "CRATES", Format: "crates"}) == nil ||
		conf(Binding{Prefix: "/crates", Volume: "s3", KeyPrefix: "CRATES", Format: "crates", URL: "https://h/elsewhere"}) == nil ||
		conf(Binding{Prefix: "/x", Volume: "s3", KeyPrefix: "X", URL: "https://h/x"}) == nil {
		t.Fatal("a crates binding without its url, with another, or a url elsewhere: taken")
	}
	bs, err := (&Config{Volumes: map[string]VolumeConf{"s3": vol}, Bindings: []Binding{{Prefix: "/crates", Volume: "s3",
		KeyPrefix: "CRATES", Format: "crates", Public: true, URL: "https://store.example.org:8444/crates"}}}).bindings()
	if err != nil {
		t.Fatal(err)
	}
	bs[0].Index = reg.URL // http: a test's
	s.bindings = append(s.bindings, bs[0])

	w := do(s, "GET", "/crates/index/config.json", nil)
	var c struct{ Dl string }
	if json.Unmarshal(w.Body.Bytes(), &c); w.Code != 200 || c.Dl != "https://store.example.org:8444/crates/crates" {
		t.Fatalf("config.json: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", "/crates/index/it/oa/itoa", nil); w.Code != 200 || len(w.Body.String()) == 0 {
		t.Fatalf("the index file: %d %s", w.Code, w.Body)
	}
	for name, cs := range map[string]struct {
		target string
		code   int
	}{
		"not its path":        {"/crates/index/xx/oa/itoa", 404},
		"no such crate":       {"/crates/index/no/ne/none", 404},
		"no such version":     {"/crates/crates/itoa/9.9.9/download", 404},
		"not a version":       {"/crates/crates/itoa/latest/download", 404},
		"uploads not allowed": {"/crates/crates/itoa/1.0.0/download?uploads", 401},
	} {
		method := "GET"
		if cs.code == 401 {
			method = "POST"
		}
		if w := do(s, method, cs.target, nil); w.Code != cs.code {
			t.Errorf("%s: want %d, got %d %s", name, cs.code, w.Code, w.Body)
		}
	}
	if indexHits.Load() != 1 {
		t.Fatalf("the index asked %d times within %s", indexHits.Load(), crateIndexTTL)
	}

	// the first read: from the registry, while the store fetches it
	key := "CRATES/files/itoa/itoa-1.0.0.crate"
	if w := do(s, "GET", "/crates/crates/itoa/1.0.0/download", nil); w.Code != 302 || w.Header().Get("Location") != reg.URL+"/dl/itoa/1.0.0/download" {
		t.Fatalf("first read: %d %v", w.Code, w.Header())
	}
	settled(t, s)
	if !m.has(key) || m.meta[key]["sha256"] != "sha256:"+cksum {
		t.Fatalf("not kept: %v", m.meta[key])
	}
	// then from the store, the registry down
	down.Store(true)
	if w := do(s, "GET", "/crates/crates/itoa/1.0.0/download", nil); w.Code != 302 || w.Header().Get("Location") == reg.URL+"/dl/itoa/1.0.0/download" {
		t.Fatalf("from the store: %d %v", w.Code, w.Header())
	}
	if w := do(s, "GET", "/crates/index/it/oa/itoa", nil); w.Code != 200 { // the index file as it was
		t.Fatalf("the index down: %d", w.Code)
	}
	// bytes not the index's checksum: not kept
	down.Store(false)
	do(s, "GET", "/crates/crates/itoa/1.0.1/download", nil)
	settled(t, s)
	if m.has("CRATES/files/itoa/itoa-1.0.1.crate") {
		t.Fatal("a crate not matching its checksum kept")
	}
}
