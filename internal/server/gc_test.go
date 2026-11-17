// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
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

func TestGCRefusesSkippedPackagesAndOddStrays(t *testing.T) {
	for name, objs := range map[string]map[string]string{
		"a package without a hash":           {"MM/release_x-1/a.el9.json": `{"build_id": "release_x-1", "packages": [{"hash": 7}]}`},
		"a stray that is no common manifest": {"CANARY/common-manifest-el9.json": `{"kind": "other", "packages": []}`},
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
	if code := GC(cfg, dir, GCOptions{Grace: time.Hour, Max: 0.25, Reads: 10}, io.Discard); code != 1 {
		t.Fatalf("-gc-reads without -gc-read: exit %d", code)
	}
	var out strings.Builder
	if code := GC(cfg, dir, ok, &out); code != 0 || !strings.Contains(out.String(), "nothing to plan") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if code := GC(cfg, dir, GCOptions{Grace: time.Hour, Max: 0.25, Out: "a", Apply: "b"}, io.Discard); code != 1 {
		t.Fatalf("-gc-out and -gc-apply: exit %d", code)
	}
	plan := filepath.Join(dir, "plan.json")
	if code := GC(cfg, dir, GCOptions{Grace: time.Hour, Max: 0.25, Out: plan}, io.Discard); code != 0 {
		t.Fatalf("-gc-out: exit %d", code)
	}
	if code := GC(cfg, dir, GCOptions{Grace: time.Hour, Max: 0.25, Apply: plan}, io.Discard); code != 0 {
		t.Fatalf("-gc-apply: exit %d", code)
	}
}

// Common manifests outside the manifests bindings (the orchestrator's CANARY/ ones)
// are read at plan time: what they list stays; one that cannot be read refuses.
func TestGCStrayRoots(t *testing.T) {
	s, m, _, plan := gcSetup(t)
	m.objs["CANARY/common-manifest-el9.json"] = []byte(`{"kind": "common-manifest", "sources": [], "packages": [{"hash": "bb22"}]}`)
	now := s.now()
	s.now = func() time.Time { return now.Add(s.verifyEvery) }
	s.verifyDue(context.Background(), map[string]time.Time{})
	s.readManifests(context.Background())
	p := plan()
	if p.Refused != "" {
		t.Fatal(p.Refused)
	}
	for _, a := range p.Arches {
		if a.Arch == "el9" && a.Sweep != 0 {
			t.Fatalf("what a stray lists swept: %+v", a)
		}
	}
	m.getFailsOn = "CANARY/common-manifest-el9.json"
	if p := plan(); !strings.Contains(p.Refused, "could not be read") {
		t.Fatalf("an unreadable stray: %q", p.Refused)
	}
	m.getFailsOn = ""
	m.objs["CANARY/common-manifest-el10.json"] = []byte(`{"kind": "common-manifest", "sources": [], "packages": []}`)
	if p := plan(); !strings.Contains(p.Refused, "new since the last listing") {
		t.Fatalf("a stray written since the listing: %q", p.Refused)
	}
	now = s.now()
	s.now = func() time.Time { return now.Add(s.verifyEvery) }
	s.verifyDue(context.Background(), map[string]time.Time{})
	if p := plan(); p.Refused != "" { // two strays, both read
		t.Fatalf("two strays: %q", p.Refused)
	}
	delete(m.objs, "CANARY/common-manifest-el10.json")
	if p := plan(); !strings.Contains(p.Refused, "could not be read") {
		t.Fatalf("a stray gone since the listing: %q", p.Refused)
	}
	m.objs["CANARY/common-manifest-el10.json"] = []byte(`{"kind": "common-manifest", "sources": [], "packages": [{"hash": 5}]}`)
	if p := plan(); !strings.Contains(p.Refused, "not all of its packages") {
		t.Fatalf("a stray with packages skipped: %q", p.Refused)
	}
}

// What was read lately, or often, stays; reads counted for less than -gc-read refuse.
func TestGCKeepsWhatIsRead(t *testing.T) {
	ctx := context.Background()
	o := GCOptions{Grace: 7 * 24 * time.Hour, Max: 0.25, Read: 30 * 24 * time.Hour, Reads: 10}
	const b = "TT/el9/store/bb/bb22/b-1-1.el9.tar.gz"
	day := 24 * time.Hour
	for _, c := range []struct {
		n     int64
		ago   time.Duration
		since time.Duration // reads counted for
		goes  bool
	}{{1, 5 * day, 31 * day, false}, {20, 60 * day, 31 * day, false}, {2, 60 * day, 31 * day, true},
		{50, 200 * day, 31 * day, true}, {0, 0, 31 * day, true},
		{10, 119 * day, 31 * day, false}, {10, 121 * day, 31 * day, true}, {9, 29 * day, 31 * day, false}} {
		s, _, x, _ := gcSetup(t)
		x.SetReadsSince(ctx, s.now().Add(-c.since))
		if c.n > 0 {
			x.AddReads(ctx, map[[2]string]index.Read{{s.place["s3"], b}: {N: c.n, Last: s.now().Add(-c.ago)}})
		}
		plans, err := s.PlanGC(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		var el9 *GCArch
		for _, a := range plans[0].Arches {
			if a.Arch == "el9" {
				el9 = a
			}
		}
		if plans[0].Refused != "" || (el9.Sweep == 1) != c.goes || (el9.Read == 1) == c.goes {
			t.Fatalf("%d reads, the last %s ago: %q %+v", c.n, c.ago, plans[0].Refused, el9)
		}
	}
	s, _, x, _ := gcSetup(t)
	x.SetReadsSince(ctx, s.now().Add(-29*day))
	if plans, _ := s.PlanGC(ctx, o); !strings.Contains(plans[0].Refused, "reads are counted since") {
		t.Fatalf("reads counted for less than -gc-read: %q", plans[0].Refused)
	}
	o.Read = 0 // no read rule: no wait
	if plans, _ := s.PlanGC(ctx, o); plans[0].Refused != "" {
		t.Fatalf("without the read rule: %q", plans[0].Refused)
	}
}

func TestGCPlanWritten(t *testing.T) {
	s, _, x, _ := gcSetup(t)
	ctx := context.Background()
	x.AddReads(ctx, map[[2]string]index.Read{{s.place["s3"], "TT/el9/store/bb/bb22/b-1-1.el9.tar.gz"}: {N: 3, Last: s.now().Add(-90 * 24 * time.Hour)}})
	o := GCOptions{Grace: 7 * 24 * time.Hour, Max: 0.25, List: true}
	plans, err := s.PlanGC(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if code := writePlan(&out, plans, o); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{`volume "s3": el10: not certified, all 1 kept`,
		`volume "s3": el9: 5 kept (61.0 B), 1 younger than 168h0m0s, 0 read lately, 2 not packages; 1 would go (3.0 B)`,
		"would go: TT/el9/store/bb/bb22/b-1-1.el9.tar.gz 3.0 B, written 0001-01-01, 3 reads, last read 20"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("no %q in:\n%s", want, out.String())
		}
	}
	o.List = false
	out.Reset()
	if writePlan(&out, plans, o); strings.Contains(out.String(), "would go: ") {
		t.Fatal("named without -gc-list")
	}
}

// The newest builds of each version stay, by write time; a file named otherwise is
// its own version; what any BOM lists stays, of a build certified or not.
func TestGCKeepsTheNewestBuilds(t *testing.T) {
	s, m, x, _ := gcSetup(t)
	ctx := context.Background()
	for i := range 5 {
		h := "z" + strconv.Itoa(i) + "zz"
		m.objs["TT/el9/store/z"+strconv.Itoa(i)+"/"+h+"/zlib-1.3-1.el9.tar.gz"] = []byte("z")
	}
	m.objs["TT/el9/store/z9/z9zz/zlib-1.2-1.el9.tar.gz"] = []byte("an older version, one build")
	m.objs["TT/el9/store/z8/z8zz/zlib-1.3-local1.el9.tar.gz"] = []byte("a local revision: a build of 1.3, the oldest")
	m.objs["PUBT/el9/store/z7/z7zz/zlib-1.3-1.el9.tar.gz"] = []byte("under another binding: not of TT's builds")
	for i := range 4 { // each its own version
		m.objs["TT/el9/store/qq/qq1"+strconv.Itoa(i)+"/odd.tar.gz"] = []byte("not named as bits names packages")
	}
	m.objs["TT/el9/store/uu/uu11/u-1-1.el9.tar.gz"] = []byte("in an uncertified build's BOM")
	m.objs["MM/release_u-1/a.el9.json"] = []byte(`{"build_id": "release_u-1", "packages": [{"hash": "uu11", "effective_architecture": "el9"}]}`)
	now := s.now()
	s.now = func() time.Time { return now.Add(s.verifyEvery) }
	s.verifyDue(ctx, map[string]time.Time{})
	s.readManifests(ctx)
	misplaced := "TT/el9/store/ee/zz99/zlib-1.3-1.el9.tar.gz" // not in its hash's folder: no build of 1.3
	m.objs[misplaced] = []byte("x")
	s.verifyDue(ctx, map[string]time.Time{})
	x.Put(ctx, s.place["s3"], index.Object{Key: misplaced, Size: 1, ETag: m.etag(misplaced), Mtime: now}, now)
	k8 := "TT/el9/store/z8/z8zz/zlib-1.3-local1.el9.tar.gz"
	x.Put(ctx, s.place["s3"], index.Object{Key: k8, Size: 1, ETag: m.etag(k8), Mtime: now.Add(-90 * 24 * time.Hour)}, now)
	for i := range 5 { // written a day apart, z4 the newest, all past the grace
		k := "TT/el9/store/z" + strconv.Itoa(i) + "/z" + strconv.Itoa(i) + "zz/zlib-1.3-1.el9.tar.gz"
		x.Put(ctx, s.place["s3"], index.Object{Key: k, Size: 1, ETag: m.etag(k), Mtime: now.Add(-60*24*time.Hour + time.Duration(i)*24*time.Hour)}, now)
	}
	plans, err := s.PlanGC(ctx, GCOptions{Grace: 7 * 24 * time.Hour, Max: 1, KeepBuilds: 3})
	if err != nil {
		t.Fatal(err)
	}
	var el9 *GCArch
	for _, a := range plans[0].Arches {
		if a.Arch == "el9" {
			el9 = a
		}
	}
	gone := map[string]bool{}
	for _, f := range el9.sweep {
		gone[f.Key] = true
	}
	// b (no manifest, one build of its version) stays as the newest of its version now
	want := []string{"TT/el9/store/z0/z0zz/zlib-1.3-1.el9.tar.gz", "TT/el9/store/z1/z1zz/zlib-1.3-1.el9.tar.gz",
		"TT/el9/store/z8/z8zz/zlib-1.3-local1.el9.tar.gz"}
	if plans[0].Refused != "" || len(gone) != 3 || !gone[want[0]] || !gone[want[1]] || !gone[want[2]] || el9.Newest != 10 {
		t.Fatalf("%q: gone %v, %d newest", plans[0].Refused, gone, el9.Newest)
	}
}

// A plan written for review, then applied: only what it names and the plan made then
// still sweeps, as planned, goes.
func TestGCApply(t *testing.T) {
	s, m, x, _ := gcSetup(t)
	ctx := context.Background()
	o := GCOptions{Grace: 7 * 24 * time.Hour, Max: 0.25}
	file := filepath.Join(t.TempDir(), "plan.json")
	gone := "TT/el9/store/bb/bb22/b-1-1.el9.tar.gz"
	write := func(f gcFile) {
		b, err := json.Marshal(f)
		if err != nil || os.WriteFile(file, b, 0o644) != nil {
			t.Fatal(err)
		}
	}
	read := func() gcFile {
		var f gcFile
		if b, err := os.ReadFile(file); err != nil || json.Unmarshal(b, &f) != nil {
			t.Fatalf("%s %v", b, err)
		}
		return f
	}
	apply := func(plans []*GCPlan) (int, string) {
		var out strings.Builder
		code := s.ApplyGC(ctx, plans, o, file, &out)
		return code, out.String()
	}
	if err := writeGCFile(file, mustPlan(t, s, o), o, s.now()); err != nil {
		t.Fatal(err)
	}
	f := read()
	if len(f.Files) != 1 || f.Files[0] != (gcFileEntry{"s3", s.place["s3"], gone, 3, m.etag(gone)}) {
		t.Fatalf("%+v", f)
	}
	planned := f.Files[0]
	// what the reviewer was not shown: a root, an uncertified architecture's, another ETag
	f.Files = append(f.Files, gcFileEntry{"s3", s.place["s3"], "TT/el9/store/aa/aa/a-1-1.el9.tar.gz", 9, "e"},
		gcFileEntry{"s3", s.place["s3"], "TT/el10/store/dd/dd44/d-1-1.el10.tar.gz", 15, m.etag("TT/el10/store/dd/dd44/d-1-1.el10.tar.gz")},
		gcFileEntry{"s3", s.place["s3"], gone, 3, "another"})
	write(f)
	if code, out := apply(nil); code != 0 || !m.has(gone) {
		t.Fatalf("no plan now, yet deleted: %d %s", code, out)
	}
	if code, out := apply(mustPlan(t, s, o)); code != 0 || m.has(gone) ||
		!strings.Contains(out, "1 deleted (3.0 B), 3 kept, of the 4") || !strings.Contains(out, "not as planned in the index") {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, k := range []string{"TT/el9/store/aa/aa/a-1-1.el9.tar.gz", "TT/el10/store/dd/dd44/d-1-1.el10.tar.gz"} {
		if !m.has(k) {
			t.Fatalf("%s deleted", k)
		}
	}
	// planned, then: other bytes of the same size in the bucket; read; listed by a new BOM
	m.objs[gone] = []byte("not")
	plans := mustPlan(t, s, o)
	write(gcFile{s.now().UTC(), fileOptions(o), []gcFileEntry{planned}})
	m.etags[gone] = "other"
	if _, out := apply(plans); !m.has(gone) || !strings.Contains(out, "changed in the bucket since planned") {
		t.Fatalf("a changed file deleted: %s", out)
	}
	delete(m.etags, gone)
	x.AddReads(ctx, map[[2]string]index.Read{{s.place["s3"], gone}: {N: 1, Last: s.now()}})
	if _, out := apply(plans); !m.has(gone) || !strings.Contains(out, "read since planned") {
		t.Fatalf("a file read since deleted: %s", out)
	}
	// a bucket that cannot answer: exit 1
	plans = mustPlan(t, s, o)
	m.statFails = gone
	if code, out := apply(plans); code != 1 || !m.has(gone) {
		t.Fatalf("a failing bucket: %d %s", code, out)
	}
	plans = mustPlan(t, s, o)
	if len(plans[0].Arches) == 0 {
		t.Fatal("no plan")
	}
	x.PutManifest(ctx, s.place["s3"], index.Manifest{Key: "MM/release_z/b.json", ETag: "z", Kind: index.KindBOM, At: s.now(),
		Builds: []string{"z"}, Entries: []index.Entry{{Arch: "el9", Hash: "bb22"}}})
	if _, out := apply(plans); !m.has(gone) || !strings.Contains(out, "a manifest lists it now") {
		t.Fatalf("a file a BOM lists since deleted: %s", out)
	}
	// a second bucket, checked on its own: a BOM there since its plan keeps its file
	m2 := newMem()
	s.stores["zz"], s.place["zz"] = m2, "https://s3.example.org zz"
	k := "TT/el9/store/ff/ff66/f-1-1.el9.tar.gz"
	m2.objs[k] = []byte("abc")
	obj := index.Object{Key: k, Size: 3, ETag: m2.etag(k), Mtime: s.now().Add(-100 * 24 * time.Hour)}
	x.Put(ctx, s.place["zz"], obj, s.now())
	m3 := newMem() // a bucket checked first, its file not listed by any manifest
	s.stores["yy"], s.place["yy"] = m3, "https://s3.example.org yy"
	k3 := "TT/el9/store/ee/ee55/e-1-1.el9.tar.gz"
	m3.objs[k3] = []byte("abc")
	obj3 := index.Object{Key: k3, Size: 3, ETag: m3.etag(k3), Mtime: obj.Mtime}
	x.Put(ctx, s.place["yy"], obj3, s.now())
	two := []*GCPlan{{Volume: "yy", bucket: s.place["yy"], Arches: []*GCArch{{Arch: "el9", sweep: []index.Object{obj3}}}},
		{Volume: "zz", bucket: s.place["zz"], Arches: []*GCArch{{Arch: "el9", sweep: []index.Object{obj}}}}}
	x.PutManifest(ctx, s.place["zz"], index.Manifest{Key: "MM/release_z/b.json", ETag: "z", Kind: index.KindBOM, At: s.now(),
		Builds: []string{"z"}, Entries: []index.Entry{{Arch: "el9", Hash: "ff66"}}})
	writeGCFile(file, two, o, s.now())
	if _, out := apply(two); !m2.has(k) || !strings.Contains(out, "kept: zz "+k+": a manifest lists it now") || m3.has(k3) {
		t.Fatalf("the second bucket's root deleted, or the first's file kept: %s", out)
	}
	// a manifest left to read (new since the plan): its volume stops, exit 2
	x.Put(ctx, s.place["zz"], index.Object{Key: "MM/release_y/new.json", Size: 2, ETag: "n"}, s.now()) // as uploaded
	two[1].mans = []string{"MM"}
	if code, out := apply(two); code != 2 || !m2.has(k) || !strings.Contains(out, `volume "zz": stopped`) {
		t.Fatalf("a manifest left to read: %d %s", code, out)
	}
	for _, v := range []string{"yy", "zz"} {
		delete(s.stores, v)
		delete(s.place, v)
	}
	// refused now: nothing goes, exit 2; a refused plan writes no file to go
	write(gcFile{s.now().UTC(), fileOptions(o), []gcFileEntry{planned}})
	if code, out := apply([]*GCPlan{{Volume: "s3", bucket: s.place["s3"], Refused: "no"}}); code != 2 || !m.has(gone) ||
		!strings.Contains(out, "its volume is refused now") {
		t.Fatalf("refused: %d %s", code, out)
	}
	plans[0].Refused = "no"
	if writeGCFile(file, plans, o, s.now()); len(read().Files) != 0 {
		t.Fatal("a refused plan's files written")
	}
	// files not as -gc-out writes them: refused
	for name, f := range map[string]func(){
		"more after it": func() {
			write(gcFile{s.now(), fileOptions(o), nil})
			b, _ := os.ReadFile(file)
			os.WriteFile(file, append(b, " {}"...), 0o644)
		},
		"unknown field":   func() { os.WriteFile(file, []byte(`{"files": [], "more": 1}`), 0o644) },
		"other options":   func() { write(gcFile{s.now(), fileOptions(GCOptions{Grace: time.Hour, Max: 0.25}), nil}) },
		"too old":         func() { write(gcFile{s.now().Add(-gcPlanLife - time.Hour), fileOptions(o), nil}) },
		"from the future": func() { write(gcFile{s.now().Add(2 * time.Hour), fileOptions(o), nil}) },
	} {
		f()
		if code, _ := apply(nil); code != 1 {
			t.Fatalf("%s: exit %d", name, code)
		}
	}
}

func mustPlan(t *testing.T, s *Server, o GCOptions) []*GCPlan {
	plans, err := s.PlanGC(context.Background(), o)
	if err != nil || len(plans) != 1 || plans[0].Refused != "" {
		t.Fatalf("%v %v", plans, err)
	}
	return plans
}
