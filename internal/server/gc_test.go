// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// gcSetup: a bucket whose signed common manifest lists hash "aa" of el9, listed and
// its manifests read with the manifest keys.
func gcSetup(t *testing.T) (*Server, *memStore, *index.Index, func() *GCPlan) {
	s, _, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	x := withIndex(t, s)
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/manifests/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	keys, err := index.ParseKeys([]string{string(read("test-key.pem"))})
	if err != nil {
		t.Fatal(err)
	}
	s.manifestKeys = keys
	m.objs["MM/common-manifest-el9.json"] = read("common-manifest-el9.json")
	m.objs["MM/common-manifest-el9.json.sig"] = read("common-manifest-el9.json.sig")
	m.objs["TT/el9/store/aa/aa/a-1-1.el9.tar.gz"] = []byte("certified")
	m.objs["TT/el9/store/bb/bb22/b-1-1.el9.tar.gz"] = []byte("not")
	m.objs["TT/el9/dist/x"] = []byte("not a package")
	m.objs["TT/el9/store/ee/xx55/e"] = []byte("its folder not its hash's")
	m.objs["TT/el10/store/dd/dd44/d-1-1.el10.tar.gz"] = []byte("never certified")
	for i := range 4 {
		m.objs["TT/el9/store/aa/aa/r"+string(rune('0'+i))] = []byte("certified too")
	}
	clock := now.Add(30 * 24 * time.Hour) // the listed files are long old
	s.now = func() time.Time { return clock }
	ctx := context.Background()
	s.verifyDue(ctx, map[string]time.Time{})
	s.readManifests(ctx)
	young := index.Object{Key: "TT/el9/store/cc/cc33/c-1-1.el9.tar.gz", Size: 5, ETag: "e", Mtime: clock.Add(-time.Hour)}
	if err := x.Put(ctx, s.place["s3"], young, clock); err != nil {
		t.Fatal(err)
	}
	plan := func() *GCPlan {
		plans, err := s.PlanGC(ctx, GCOptions{Grace: 7 * 24 * time.Hour, Max: 0.25})
		if err != nil || len(plans) != 1 {
			t.Fatalf("%v %v", plans, err)
		}
		return plans[0]
	}
	return s, m, x, plan
}

func TestGCPlan(t *testing.T) {
	_, _, _, plan := gcSetup(t)
	p := plan()
	if p.Refused != "" || p.Volume != "s3" || len(p.Arches) != 2 {
		t.Fatalf("%+v", p)
	}
	el10, el9 := p.Arches[0], p.Arches[1]
	if el10.Arch != "el10" || el10.Certified || el10.Sweep != 0 || el10.Kept != 1 {
		t.Fatalf("an architecture never certified: %+v", el10)
	}
	if el9.Kept != 5 || el9.Young != 1 || el9.Other != 2 || el9.Sweep != 1 ||
		el9.sweep[0].Key != "TT/el9/store/bb/bb22/b-1-1.el9.tar.gz" || el9.SweepBytes != 3 {
		t.Fatalf("el9: %+v", el9)
	}
}

// What may not stand for the store refuses the whole bucket.
func TestGCRefuses(t *testing.T) {
	for name, change := range map[string]func(s *Server, m *memStore){
		"no manifest keys": func(s *Server, m *memStore) { s.manifestKeys = nil },
		"an old listing": func(s *Server, m *memStore) {
			now := s.now()
			s.now = func() time.Time { return now.Add(s.verifyEvery + 3*time.Hour) }
		},
		"a common manifest changed": func(s *Server, m *memStore) {
			m.objs["MM/common-manifest-el9.json"] = append(m.objs["MM/common-manifest-el9.json"], ' ')
		},
		"its .sig changed": func(s *Server, m *memStore) { m.objs["MM/common-manifest-el9.json.sig"] = []byte(`{}`) },
		"its .sig gone":    func(s *Server, m *memStore) { delete(m.objs, "MM/common-manifest-el9.json.sig") },
		"a new common manifest": func(s *Server, m *memStore) {
			m.objs["MM/common-manifest-el10.json"] = []byte(`{"kind": "common-manifest", "sources": [], "packages": []}`)
		},
		"a common manifest gone": func(s *Server, m *memStore) { delete(m.objs, "MM/common-manifest-el9.json") },
		"too much would go": func(s *Server, m *memStore) {
			for i := range 3 { // with b, 4 of 9 packages: more than a quarter
				m.objs["TT/el9/store/f"+string(rune('0'+i))+"/f"+string(rune('0'+i))+"x/f"] = []byte("x")
			}
			now := s.now()
			s.now = func() time.Time { return now.Add(s.verifyEvery) }
			s.verifyDue(context.Background(), map[string]time.Time{})
		},
	} {
		s, m, _, plan := gcSetup(t)
		change(s, m)
		if p := plan(); p.Refused == "" {
			t.Fatalf("%s: not refused: %+v", name, p.Arches)
		} else {
			t.Logf("%s: %s", name, p.Refused)
		}
	}
	// a manifest that could not be read
	s, m, _, plan := gcSetup(t)
	m.objs["MM/release_x-1/a.el9.json"] = []byte(`{}`)
	now := s.now()
	s.now = func() time.Time { return now.Add(s.verifyEvery) }
	s.verifyDue(context.Background(), map[string]time.Time{})
	m.getFailsOn = "MM/release_x-1/a.el9.json"
	s.readManifests(context.Background())
	if p := plan(); !strings.Contains(p.Refused, "could not be read") {
		t.Fatalf("an unread manifest: %q", p.Refused)
	}
}

// Roots are wide: what any common manifest lists, the BOMs of their sources, and
// young BOMs; only verified common manifests make an architecture sweepable.
func TestGCRootsAreWide(t *testing.T) {
	s, m, x, plan := gcSetup(t)
	ctx := context.Background()
	m.objs["MM/release_x-1/a.el9.json"] = []byte(`{"build_id": "release_x-1", "packages": [{"hash": "BB22", "effective_architecture": "el9"}]}`)
	m.objs["TT/el9/store/gg/gg77/g"] = []byte("by a young BOM")
	m.objs["TT/el9/store/hh/hh88/h"] = []byte("by an unsigned common manifest")
	m.objs["MM/common-manifest-el8.json"] = []byte(`{"kind": "common-manifest", "sources": [], "packages": [{"hash": "hh88", "effective_architecture": "el8"}]}`)
	now := s.now()
	s.now = func() time.Time { return now.Add(s.verifyEvery) }
	s.verifyDue(ctx, map[string]time.Time{})
	s.readManifests(ctx)
	young := index.Manifest{Key: "MM/release_y-1/a.el9.json", ETag: "e", Kind: index.KindBOM, At: s.now(),
		Builds: []string{"release_y-1"}, Entries: []index.Entry{{Arch: "el9", Hash: "gg77"}}}
	x.Put(ctx, s.place["s3"], index.Object{Key: young.Key, Size: 1, ETag: "e", Mtime: s.now()}, s.now())
	if err := x.PutManifest(ctx, s.place["s3"], young); err != nil {
		t.Fatal(err)
	}
	p := plan()
	if p.Refused != "" {
		t.Fatal(p.Refused)
	}
	for _, a := range p.Arches {
		if a.Arch == "el9" && (a.Sweep != 0 || a.Kept != 8) {
			t.Fatalf("el9: %+v", a)
		}
	}
}

func TestGCRefusesSkippedPackagesAndStrays(t *testing.T) {
	for name, objs := range map[string]map[string]string{
		"a package without a hash":           {"MM/release_x-1/a.el9.json": `{"build_id": "release_x-1", "packages": [{"hash": 7}]}`},
		"a common manifest no binding reads": {"TT/common-manifest-el9.json": `{"kind": "common-manifest", "sources": [], "packages": []}`},
	} {
		s, m, _, plan := gcSetup(t)
		for k, v := range objs {
			m.objs[k] = []byte(v)
		}
		now := s.now()
		s.now = func() time.Time { return now.Add(s.verifyEvery) }
		s.verifyDue(context.Background(), map[string]time.Time{})
		s.readManifests(context.Background())
		if p := plan(); p.Refused == "" {
			t.Fatalf("%s: not refused", name)
		} else {
			t.Logf("%s: %s", name, p.Refused)
		}
	}
}

// -gc reads the service's index, never writes it, and checks what it is given.
func TestGCCommand(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/tokens/vectors.json")
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	c, _ := json.Marshal(Config{Issuer: v.Issuer, Audience: v.Audience, Keys: v.Keys,
		Volumes:  map[string]VolumeConf{"pub": {Endpoint: "https://s3.example.org", Bucket: "open", Region: "us-east-1"}},
		Bindings: []Binding{{Prefix: "/public", Volume: "pub", Public: true}}})
	os.WriteFile(cfg, c, 0o644)
	ok := GCOptions{Grace: time.Hour, Max: 0.25}
	for name, run := range map[string]func() int{
		"no -data":       func() int { return GC(cfg, "", ok, io.Discard) },
		"no index there": func() int { return GC(cfg, dir, ok, io.Discard) },
		"no grace":       func() int { return GC(cfg, dir, GCOptions{Max: 0.25}, io.Discard) },
		"max NaN":        func() int { return GC(cfg, dir, GCOptions{Grace: time.Hour, Max: math.NaN()}, io.Discard) },
		"max above 1":    func() int { return GC(cfg, dir, GCOptions{Grace: time.Hour, Max: 2}, io.Discard) },
	} {
		if code := run(); code != 1 {
			t.Fatalf("%s: exit %d", name, code)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "index.db")); err == nil {
		t.Fatal("an index created")
	}
	x, err := index.Open(filepath.Join(dir, "index.db")) // the service's
	if err != nil {
		t.Fatal(err)
	}
	x.Close()
	var out strings.Builder
	if code := GC(cfg, dir, ok, &out); code != 0 || !strings.Contains(out.String(), "nothing to plan") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}
