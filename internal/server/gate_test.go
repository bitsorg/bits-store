// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/bitsorg/bits-store/internal/index"
	"github.com/bitsorg/bits-store/internal/token"
)

func TestGateConfig(t *testing.T) {
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	for name, ok := range map[string]bool{"group tarballs": true, " blob": true, "group blob": false,
		"user tarballs": false, "group tarballs public": false, "group tarballs elsewhere": false,
		"group tarballs readers": true, " tarballs readers": false, "group tarballs readers-empty": false,
		"group tarballs readers-of-none": false, "group tarballs shared": false} {
		f := strings.Split(name, " ")
		keyed := VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bucket", Region: "r",
			AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
		alias := keyed
		alias.Endpoint = "https://alias.example.org"
		c := &Config{Issuer: "i", Audience: "a",
			Keys:     map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
			Volumes:  map[string]VolumeConf{"k": keyed, "alias": alias},
			Bindings: []Binding{{Prefix: "/r", Volume: "k", KeyPrefix: "R", Format: f[1], Gate: f[0], Public: len(f) > 2 && f[2] == "public"}}}
		switch {
		case len(f) > 2 && f[2] == "readers":
			c.Bindings[0].Readers = map[string][]string{"sft": {"lhcb"}}
		case len(f) > 2 && f[2] == "readers-empty":
			c.Bindings[0].Readers = map[string][]string{"sft": {""}}
		case len(f) > 2 && f[2] == "readers-of-none": // would read all of no known writer
			c.Bindings[0].Readers = map[string][]string{"": {"cms"}}
		case len(f) > 2 && f[2] == "shared": // the same bucket, not gated
			c.Bindings = append(c.Bindings, Binding{Prefix: "/o", Volume: "k", KeyPrefix: "O"})
		}
		if len(f) > 2 && f[2] == "elsewhere" { // the same bucket by another endpoint: not gated
			c.Bindings = append(c.Bindings, Binding{Prefix: "/o", Volume: "alias", KeyPrefix: "O"})
		}
		if _, err := New(c); (err == nil) != ok || err != nil && !strings.Contains(err.Error(), "gate") && !strings.Contains(err.Error(), "readers") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// gated makes the tarballs binding .../t gated; its build tarHash on x86_64-el9 is
// stored, written by writer ("": no metadata).
func gated(t *testing.T, writer string) (*Server, *memStore, map[string]string) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	for i := range s.bindings {
		if strings.HasSuffix(s.bindings[i].Prefix, "-opt/t") {
			s.bindings[i].Gate = "group"
		}
	}
	m.objs[tarDir+"/"+tarName] = []byte("tarball")
	if writer != "" {
		m.meta[tarDir+"/"+tarName] = map[string]string{"bits-group": writer}
	}
	return s, m, map[string]string{"Authorization": "Bearer " + tok} // group lhcb
}

func TestTheGate(t *testing.T) {
	ctx := context.Background()
	key := tarDir + "/" + tarName
	for name, c := range map[string]struct {
		writer  string // the object's metadata
		indexed string // its index row's group; "-": no row; "none": no index
		readers map[string][]string
		code    int
	}{
		"the writer":              {"lhcb", "lhcb", nil, 302},
		"another group":           {"atlas", "atlas", nil, 404},
		"the writer, not indexed": {"lhcb", "-", nil, 302},
		"the writer, not known":   {"lhcb", "", nil, 302},
		"no writer":               {"", "", nil, 404},
		"no writer, readers":      {"", "", map[string][]string{"atlas": {"lhcb"}}, 404},
		"the index wins":          {"lhcb", "atlas", nil, 404},
		"no index":                {"lhcb", "none", nil, 404},
		"a reader":                {"atlas", "atlas", map[string][]string{"atlas": {"cms", "lhcb"}}, 302},
		"a reader of another":     {"atlas", "atlas", map[string][]string{"cms": {"lhcb"}}, 404},
		"not a reader":            {"atlas", "atlas", map[string][]string{"atlas": {"cms"}}, 404},
		"readers of the reader":   {"atlas", "atlas", map[string][]string{"lhcb": {"atlas"}}, 404},
	} {
		s, _, auth := gated(t, c.writer)
		gate(s).Readers = c.readers
		if c.indexed != "none" {
			x := withIndex(t, s)
			if c.indexed != "-" {
				x.Put(ctx, s.place["s3"], index.Object{Key: key, Size: 7, ETag: "e", Grp: c.indexed}, s.now())
			}
		}
		for _, method := range []string{"GET", "HEAD"} {
			w := do(s, method, tarPath, auth)
			if w.Code != c.code || c.code == 404 && w.Header().Get("Bits-Object-Name") != "" {
				t.Fatalf("%s %s: %d %v", name, method, w.Code, w.Header())
			}
		}
	}
}

func gate(s *Server) *Binding {
	for i := range s.bindings {
		if s.bindings[i].Gate != "" {
			return &s.bindings[i]
		}
	}
	return nil
}

// A token without a group reads nothing gated, not even what no group wrote.
func TestTheGateWantsAGroup(t *testing.T) {
	s, _, _ := gated(t, "")
	withIndex(t, s)
	gate(s).Readers = map[string][]string{"lhcb": {"atlas"}}
	for _, grp := range []string{"", "lhcb", "atlas"} {
		if ok, err := s.admits(context.Background(), gate(s), &token.Token{Grp: grp}, tarDir+"/"+tarName); ok || err != nil {
			t.Fatalf("group %q admitted: %v", grp, err)
		}
	}
}

// The writer read from the object is kept; a failing store is no 404.
func TestTheGateLearnsTheWriter(t *testing.T) {
	ctx := context.Background()
	key := tarDir + "/" + tarName
	s, m, auth := gated(t, "lhcb")
	x := withIndex(t, s)
	x.Put(ctx, s.place["s3"], index.Object{Key: key, Size: 7, ETag: m.etag(key)}, s.now())
	if w := do(s, "GET", tarPath, auth); w.Code != 302 {
		t.Fatalf("the writer: %d", w.Code)
	}
	if o, _ := indexed(t, s, "s3", key); o.Grp != "lhcb" {
		t.Fatalf("the writer not kept: %+v", o)
	}
	x.Put(ctx, s.place["s3"], index.Object{Key: key, Size: 7, ETag: m.etag(key)}, s.now())
	m.statFails = key
	if w := do(s, "GET", tarPath, auth); w.Code != 502 {
		t.Fatalf("a failing store: %d", w.Code)
	}
	// a row of other bytes than the object read: not its writer
	x.Put(ctx, s.place["s3"], index.Object{Key: key, Size: 7, ETag: "other"}, s.now())
	if w := do(s, "GET", tarPath, auth); w.Code != 302 {
		t.Fatalf("the writer: %d", w.Code)
	}
	if o, _ := indexed(t, s, "s3", key); o.Grp != "" {
		t.Fatalf("the writer of other bytes kept: %+v", o)
	}
}

// A gate reads builds only: a binding naming objects by key is refused.
func TestTheGateReadsBuildsOnly(t *testing.T) {
	s, m, auth := gated(t, "lhcb")
	withIndex(t, s)
	for i := range s.bindings {
		if s.bindings[i].Prefix == "/store/lhcb" {
			s.bindings[i].Gate = "group"
		}
	}
	m.objs["TARS/x86_64-el10-gcc14-opt/ab/h"] = []byte("x")
	m.meta["TARS/x86_64-el10-gcc14-opt/ab/h"] = map[string]string{"bits-group": "lhcb"}
	if w := do(s, "GET", "/store/lhcb/x86_64-el10-gcc14-opt/ab/h", auth); w.Code != 404 {
		t.Fatalf("a key behind a gate: %d", w.Code)
	}
}
