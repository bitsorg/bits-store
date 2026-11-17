// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
	"github.com/bitsorg/bits-store/internal/token"
)

func TestGateConfig(t *testing.T) {
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	for name, ok := range map[string]bool{"group tarballs": true, " blob": true, "group blob": false,
		"user tarballs": false, "group tarballs public": false, "group tarballs elsewhere": false,
		"group tarballs readers": true, " tarballs readers": false, "group tarballs readers-bad": false,
		"group tarballs readers-of-bad": false, "group tarballs shared": false, "group tarballs unsigned": false,
		" tarballs unsigned": true} {
		f := strings.Split(name, " ")
		keyed := VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bucket", Region: "r",
			AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
		alias := keyed
		alias.Endpoint = "https://alias.example.org"
		c := &Config{Issuer: "i", Audience: "a",
			Keys:             map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
			Volumes:          map[string]VolumeConf{"k": keyed, "alias": alias},
			Bindings:         []Binding{{Prefix: "/r", Volume: "k", KeyPrefix: "R", Format: f[1], Gate: f[0], Public: len(f) > 2 && f[2] == "public"}},
			RestrictedSigner: SignerConf{AgentSocket: "/run/agent.sock", Route: "r", Host: "signer", Prefix: "/sign/r"}}
		switch {
		case len(f) < 3:
		case f[2] == "readers":
			c.Bindings[0].Readers = map[string][]string{"sft": {"lhcb"}}
		case f[2] == "readers-bad":
			c.Bindings[0].Readers = map[string][]string{"sft": {"LHCb"}}
		case f[2] == "readers-of-bad":
			c.Bindings[0].Readers = map[string][]string{"../x": {"cms"}}
		case f[2] == "unsigned":
			c.RestrictedSigner = SignerConf{}
		case f[2] == "shared": // the same bucket, not gated
			c.Bindings = append(c.Bindings, Binding{Prefix: "/o", Volume: "k", KeyPrefix: "O"})
		case f[2] == "elsewhere": // the same bucket by another endpoint, not gated
			c.Bindings = append(c.Bindings, Binding{Prefix: "/o", Volume: "alias", KeyPrefix: "O"})
		}
		if _, err := New(c); (err == nil) != ok || err != nil && !strings.Contains(err.Error(), "gate") && !strings.Contains(err.Error(), "readers") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// gated makes the tarballs binding .../t gated (key prefix TT), its builds signed
// by a stand-in proxy; the vectors' token is lhcb's.
func gated(t *testing.T) (*Server, *memStore, string) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	gate(s).Gate = "group"
	var err error
	if s.signer, err = newSigner(newStandIn(t).conf); err != nil {
		t.Fatal(err)
	}
	return s, m, tok
}

func gate(s *Server) *Binding {
	for i := range s.bindings {
		if strings.HasSuffix(s.bindings[i].Prefix, "-opt/t") {
			return &s.bindings[i]
		}
	}
	return nil
}

// the key of tarHash's build filed under group g ("": not under one)
func filed(g string) string {
	return strings.Replace(tarDir, "TT/", "TT/"+g+"/", 1) + "/" + tarName
}

func TestTheGateReads(t *testing.T) {
	for name, c := range map[string]struct {
		groups  []string // that have the build
		readers map[string][]string
		from    string // the group read from; "": 404
	}{
		"its own":              {[]string{"lhcb"}, nil, "lhcb"},
		"another's":            {[]string{"atlas"}, nil, ""},
		"another's, a reader":  {[]string{"atlas"}, map[string][]string{"atlas": {"cms", "lhcb"}}, "atlas"},
		"not a reader":         {[]string{"atlas"}, map[string][]string{"atlas": {"cms"}}, ""},
		"a reader of another":  {[]string{"atlas"}, map[string][]string{"cms": {"lhcb"}}, ""},
		"its own first":        {[]string{"atlas", "lhcb"}, map[string][]string{"atlas": {"lhcb"}}, "lhcb"},
		"readers, in order":    {[]string{"cms", "atlas"}, map[string][]string{"cms": {"lhcb"}, "atlas": {"lhcb"}}, "atlas"},
		"none, under no group": {[]string{""}, nil, ""},
	} {
		s, m, tok := gated(t)
		gate(s).Readers = c.readers
		for _, g := range c.groups {
			m.objs[strings.Replace(filed(g), "TT//", "TT/", 1)] = []byte("tarball")
		}
		for _, method := range []string{"GET", "HEAD"} {
			w := do(s, method, tarPath, map[string]string{"Authorization": "Bearer " + tok})
			if c.from == "" && (w.Code != 404 || w.Header().Get("Bits-Object-Name") != "" || w.Header().Get("Bits-Object-Group") != "") ||
				c.from != "" && (w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "/"+filed(c.from)+"?") ||
					w.Header().Get("Bits-Object-Group") != c.from) {
				t.Fatalf("%s %s: %d %v", name, method, w.Code, w.Header())
			}
		}
	}
}

// A write is filed under its group: another group's build of the hash is no conflict,
// nor its upload another's to complete, nor its build another's to read.
func TestTheGateFilesWrites(t *testing.T) {
	s, m, tok := gated(t)
	atlas := tokenNamed(t, "grp-grants-nothing") // the same capabilities
	m.objs[filed("atlas")] = []byte("theirs")
	data := []byte("tarball")
	st := startNamed(t, s, tok, tarName, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, tarPath+"?complete="+st.ID, atlas, ""); w.Code != 404 {
		t.Fatalf("another group completes it: %d", w.Code)
	}
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	if string(m.objs[filed("lhcb")]) != "tarball" || m.meta[filed("lhcb")]["bits-group"] != "lhcb" {
		t.Fatalf("not filed under its group: %v", m.objs)
	}
	if w := post(s, tarPath+"?uploads", tok, named(tarName, data)); w.Code != 409 {
		t.Fatalf("its own build again: %d", w.Code)
	}
	delete(m.objs, filed("atlas"))
	if w := do(s, "GET", tarPath, map[string]string{"Authorization": "Bearer " + atlas}); w.Code != 404 {
		t.Fatalf("lhcb's read by atlas: %d %v", w.Code, w.Header())
	}
	other := startNamed(t, s, atlas, tarName, data)
	m.upload("STAGING/"+other.ID, data)
	if w := post(s, tarPath+"?complete="+other.ID, atlas, ""); w.Code != 201 || m.meta[filed("atlas")]["bits-group"] != "atlas" {
		t.Fatalf("complete: %d %v", w.Code, m.objs)
	}
}

// Only a plain group name reads or writes behind a gate.
func TestTheGateWantsAGroup(t *testing.T) {
	s, _, _ := gated(t)
	gate(s).Readers = map[string][]string{"atlas": {"lhcb"}}
	for grp, want := range map[string]int{"": 0, "../x": 0, "LHCb": 0, "lhcb": 2, "cms": 1} {
		if got := readable(gate(s), &token.Token{Grp: grp}); len(got) != want {
			t.Fatalf("group %q reads %v", grp, got)
		}
	}
	if readable(gate(s), nil) != nil {
		t.Fatal("no token reads")
	}
}

// The store gauges count a gated binding's builds by architecture, not by group.
func TestGatedBuildsByArchitecture(t *testing.T) {
	s, _, _ := gated(t)
	x := withIndex(t, s)
	ctx := context.Background()
	at := s.place["s3"]
	x.Put(ctx, at, index.Object{Key: filed("lhcb"), Size: 7, ETag: "e"}, s.now())
	x.Put(ctx, at, index.Object{Key: "PUBT/x86_64-el9/store/01/" + tarHash + "/" + tarName, Size: 5, ETag: "e"}, s.now())
	x.Verify(ctx, at, s.now().Add(-1), func(func(index.Object) error) error { return nil })
	w := do(s, "GET", "/metrics", nil)
	body := w.Body.String()
	if !strings.Contains(body, `bits_store_bytes{volume="s3",arch="x86_64-el9"} 12`) || strings.Contains(body, `arch="lhcb"`) ||
		!strings.Contains(body, `manifest="(restricted)",arch="x86_64-el9",signed="0"} 7`) {
		t.Fatalf("%d\n%s", w.Code, body)
	}
}

// A gate holds builds only: a binding naming objects by key is refused.
func TestTheGateHoldsBuildsOnly(t *testing.T) {
	s, m, tok := gated(t)
	for i := range s.bindings {
		if s.bindings[i].Prefix == "/store/lhcb" {
			s.bindings[i].Gate = "group"
		}
	}
	m.objs["TARS/x86_64-el10-gcc14-opt/ab/h"] = []byte("x")
	m.objs["TARS/lhcb/x86_64-el10-gcc14-opt/ab/h"] = []byte("x")
	if w := do(s, "GET", "/store/lhcb/x86_64-el10-gcc14-opt/ab/h", map[string]string{"Authorization": "Bearer " + tok}); w.Code != 404 {
		t.Fatalf("a key behind a gate: %d", w.Code)
	}
}

// A gated binding's builds (its own bucket) are planned by group and architecture,
// without manifests: kept when young, read lately or among the newest of their version.
func TestGCPlansTheGate(t *testing.T) {
	s, _, x, _ := gcSetup(t)
	ctx := context.Background()
	g := gate(s)
	g.Gate, g.Volume = "group", "priv"
	s.stores["priv"], s.place["priv"] = newMem(), "https://s3.example.org priv"
	at, old := s.place["priv"], s.now().Add(-100*24*time.Hour)
	put := func(key string, mtime time.Time) {
		x.Put(ctx, at, index.Object{Key: key, Size: 1, ETag: "e", Mtime: mtime}, s.now())
	}
	for _, r := range []string{"1", "2", "3", "4"} { // the 3 newest builds of x 1 stay
		put("TT/lhcb/el9/store/aa/aa"+r+"/x-1-"+r+".el9.tar.gz", old.Add(time.Duration(len(r)+int(r[0]))*time.Hour))
	}
	put("TT/lhcb/el9/store/bb/bb1/y-1-1.el9.tar.gz", old)      // read lately
	put("TT/lhcb/el9/store/bb/bb2/z-1-1.el9.tar.gz", old)      // alone in its version: its newest
	put("TT/atlas/el9/store/cc/cc1/x-1-1.el9.tar.gz", s.now()) // young
	put("TT/Bad_Group/el9/store/dd/dd1/x-1-1.el9.tar.gz", old) // not under a group: never
	x.AddReads(ctx, map[[2]string]index.Read{{at, "TT/lhcb/el9/store/bb/bb1/y-1-1.el9.tar.gz"}: {N: 1, Last: s.now()}})
	x.Verify(ctx, at, s.now().Add(-time.Minute), func(func(index.Object) error) error { return nil })
	plans, err := s.PlanGC(ctx, GCOptions{Grace: 7 * 24 * time.Hour, Read: 30 * 24 * time.Hour, KeepBuilds: 3, Max: 1})
	if err != nil {
		t.Fatal(err)
	}
	var p *GCPlan
	for _, q := range plans {
		if q.bucket == at {
			p = q
		}
	}
	if p == nil || len(p.Arches) != 3 || p.Arches[0].Arch != "Bad_Group/el9" || p.Arches[0].Other != 1 ||
		p.Arches[1].Arch != "atlas/el9" || p.Arches[2].Arch != "lhcb/el9" {
		t.Fatalf("%+v", p)
	}
	p.Arches = p.Arches[1:]
	lhcb := p.Arches[1]
	var gone []string
	for _, o := range lhcb.sweep {
		gone = append(gone, o.Key)
	}
	if p.Arches[0].Young != 1 || lhcb.Read != 1 || lhcb.Newest != 4 || !slices.Equal(gone, []string{
		"TT/lhcb/el9/store/aa/aa1/x-1-1.el9.tar.gz"}) {
		t.Fatalf("%+v %+v %v", p.Arches[0], lhcb, gone)
	}
	// refused: too much of a group to go; reads counted too short a time; not listed lately
	refused := func(o GCOptions, why string) {
		t.Helper()
		plans, _ := s.PlanGC(ctx, o)
		for _, q := range plans {
			if q.bucket == at && strings.Contains(q.Refused, why) {
				return
			}
		}
		t.Fatalf("not refused for %q", why)
	}
	refused(GCOptions{Grace: 7 * 24 * time.Hour, Read: 30 * 24 * time.Hour, KeepBuilds: 3, Max: 0.1}, "more than 0.1")
	refused(GCOptions{Grace: 7 * 24 * time.Hour, Read: 900 * 24 * time.Hour, Max: 1}, "reads are counted since")
	s.now = func() time.Time { return time.Now().Add(400 * 24 * time.Hour) }
	refused(GCOptions{Grace: 7 * 24 * time.Hour, Max: 1}, "last listing")
}

// Each build stored behind a gate carries its signature: of its architecture, hash,
// group, name and declared sha256. Unsigned, nothing is stored.
func TestTheGateSignsItsBuilds(t *testing.T) {
	s, m, tok := gated(t)
	g := newStandIn(t)
	s.signer, _ = newSigner(g.conf)
	data := []byte("tarball")
	g.fail.Store(true)
	if w := post(s, tarPath+"?uploads", tok, named(tarName, data)); w.Code != 503 || !strings.Contains(w.Body.String(), "unsigned") {
		t.Fatalf("unsigned: %d %s", w.Code, w.Body)
	}
	if n := len(s.uploads.m); n != 0 {
		t.Fatalf("an unsigned upload kept: %d", n)
	}
	g.fail.Store(false)
	st := startNamed(t, s, tok, tarName, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	kid, sig64, _ := strings.Cut(m.meta[filed("lhcb")]["bits-signature"], ":")
	sig, _ := base64.StdEncoding.DecodeString(sig64)
	sum := sha256.Sum256(data)
	want := restrictedStatement("x86_64-el9", tarHash, "lhcb", tarName, hex.EncodeToString(sum[:]))
	pubSum := sha256.Sum256(g.pub)
	if kid != hex.EncodeToString(pubSum[:8]) || !ed25519.Verify(g.pub, want, sig) || g.signed.Load() != 1 {
		t.Fatalf("not signed as stored: %v", m.meta[filed("lhcb")])
	}
	// an ungated binding signs nothing
	other := []byte("other")
	st = start(t, s, final, tok, other)
	m.upload("STAGING/"+st.ID, other)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 || m.meta[finalKey]["bits-signature"] != "" || g.signed.Load() != 1 {
		t.Fatalf("an ungated build signed: %d %v", w.Code, m.meta[finalKey])
	}
}
