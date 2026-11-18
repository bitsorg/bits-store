// SPDX-License-Identifier: Apache-2.0

package index

import (
	"database/sql"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const bom = `{"build_id": "release_x-1", "effective_architecture": "el9", "packages": [
 {"package": "ROOT", "version": "6", "hash": "aa", "effective_architecture": "el9"},
 {"package": "zlib", "version": "1", "hash": "bb"},
 {"package": "zlib", "version": "1", "hash": "bb"},
 {"package": "nohash", "version": "1"},
 "not an object", {"package": "odd", "hash": 7}]}`

const common = `{"kind": "common-manifest", "sources": ["release_x-1", "release_y-2"], "packages": [
 {"package": "ROOT", "version": "6", "hash": "aa", "effective_architecture": "el9"}]}`

func TestParse(t *testing.T) {
	m := Parse("MANIFESTS/release_x-1/p5-a.el9.json", "e", []byte(bom))
	want := []Entry{{"el9", "aa", "ROOT", "6"}, {"el9", "bb", "zlib", "1"}} // the BOM's arch; once each
	if m.Kind != KindBOM || !slices.Equal(m.Builds, []string{"release_x-1"}) || !slices.Equal(m.Entries, want) || m.Skipped != 2 {
		t.Fatalf("BOM: %+v", m)
	}
	if m := Parse("MANIFESTS/common-manifest-el9.json", "e", []byte(strings.Replace(common, `"release_y-2"`, `"release_y-2", 3, ""`, 1))); m.Kind != KindCommon ||
		!slices.Equal(m.Builds, []string{"release_x-1", "release_y-2"}) || len(m.Entries) != 1 {
		t.Fatalf("common manifest: %+v", m)
	}
	if m := Parse("MANIFESTS/x/a.json", "e", []byte(`{"build_id": "x", "packages": [{"hash": ""}, {"package": "p"}]}`)); m.Kind != KindBOM ||
		m.Skipped != 0 || m.Entries != nil { // packages not stored, as bits writes them: nothing unknown
		t.Fatalf("no hash: %+v", m)
	}
	for name, body := range map[string]string{
		"MANIFESTS/x/common-manifest-el9.json": `{"kind": "other", "packages": []}`, // a common manifest's name, not its kind
		"MANIFESTS/x/sbom.spdx.json":           `{"spdxVersion": "SPDX-2.3", "packages": [{"name": "x"}]}`,
		"MANIFESTS/x/broken.json":              `{"build_id": "x", "packages": [`,
		"MANIFESTS/x/odd.json":                 `{"build_id": "x", "packages": "not a list"}`,
		"MANIFESTS/orchestrator.json":          `{"owner": "bits-orchestrator"}`,
	} {
		if m := Parse(name, "e", []byte(body)); m.Kind != KindNone || m.Entries != nil {
			t.Fatalf("%s: %+v", name, m)
		}
	}
}

func TestManifestsFollowTheirObjects(t *testing.T) {
	x, _ := open(t)
	now := time.UnixMilli(1_000_000)
	put := func(key, etag string) { x.Put(ctx, "b", Object{Key: key, Size: 10, ETag: etag}, now) }
	put("MANIFESTS/release_x-1/a.el9.json", "e1")
	put("MANIFESTS/release_x-1/NOTICE", "e")
	put("MANIFESTS/rev-index/el9/ROOT/6-1.json", "e") // a marker, never read
	put("MANIFESTS/common-manifest-el9.json", "e")
	put("TARS/el9/x.json", "e") // not under the prefix
	keys := func() (out []string) {
		todo, err := x.ManifestsToRead(ctx, "b", "MANIFESTS", "", now, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range todo {
			out = append(out, o.Key)
		}
		return out
	}
	if got := keys(); !slices.Equal(got, []string{"MANIFESTS/common-manifest-el9.json", "MANIFESTS/release_x-1/a.el9.json"}) {
		t.Fatalf("to read: %v", got)
	}
	if todo, _ := x.ManifestsToRead(ctx, "b", "MANIFESTS", "", now, 1); len(todo) != 1 {
		t.Fatal("the limit not kept")
	}
	put("rev-index/el9/ROOT/6-1.json", "e") // the bucket's own markers, for a binding at its root
	if todo, _ := x.ManifestsToRead(ctx, "b", "", "", now, 10); len(todo) != 4 {
		t.Fatalf("the whole bucket: %v", todo)
	}
	x.PutManifest(ctx, "b", Parse("MANIFESTS/release_x-1/a.el9.json", "e1", []byte(bom)))
	x.PutManifest(ctx, "b", Parse("MANIFESTS/common-manifest-el9.json", "e", []byte(common)))
	if got := keys(); len(got) != 0 {
		t.Fatalf("read again: %v", got)
	}
	put("MANIFESTS/release_x-1/a.el9.json", "e2") // changed: read again, its rows replaced
	if got := keys(); !slices.Equal(got, []string{"MANIFESTS/release_x-1/a.el9.json"}) {
		t.Fatalf("a changed file: %v", got)
	}
	x.PutManifest(ctx, "b", Parse("MANIFESTS/release_x-1/a.el9.json", "e2", []byte(`{"build_id": "release_z-3", "packages": []}`)))
	if kind, builds, _ := x.Builds(ctx, "b", "MANIFESTS/release_x-1/a.el9.json"); kind != KindBOM ||
		!slices.Equal(builds, []string{"release_z-3"}) || entries(t, x) != 1 {
		t.Fatalf("replaced: %s %v, %d entries", kind, builds, entries(t, x))
	}
	// the common manifest's object gone (a listing): its rows go
	x.Verify(ctx, "b", now.Add(time.Hour), listing(Object{Key: "MANIFESTS/release_x-1/a.el9.json", Size: 10, ETag: "e2"}))
	if n, err := x.DropGoneManifests(ctx, "b"); n != 1 || err != nil || entries(t, x) != 0 {
		t.Fatalf("dropped %d, %v; %d entries left", n, err, entries(t, x))
	}
	if kind, builds, _ := x.Builds(ctx, "b", "MANIFESTS/common-manifest-el9.json"); kind != "" || builds != nil {
		t.Fatalf("its sources kept: %v", builds)
	}
	if kind, _, _ := x.Builds(ctx, "b", "MANIFESTS/release_x-1/a.el9.json"); kind != KindBOM {
		t.Fatal("a manifest still there dropped")
	}
}

func entries(t *testing.T, x *Index) (n int) {
	if err := x.db.QueryRow(`SELECT count(*) FROM manifest_entries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// An index file of another layout is dropped, to be filled again by a listing.
func TestAnOlderIndexIsDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE objects (bucket TEXT, key TEXT, size INTEGER)`) // v0.2.0's, say, at user_version 0
	db.Exec(`INSERT INTO objects VALUES ('b', 'k', 1)`)
	db.Close()
	newer := filepath.Join(t.TempDir(), "index.db") // a later release's: dropped too, not misread
	if db, err := sql.Open("sqlite", "file:"+newer); err == nil {
		db.Exec(`CREATE TABLE objects (bucket TEXT, key TEXT, size INTEGER)`)
		db.Exec(`PRAGMA user_version = 99`)
		db.Close()
	}
	if z, err := Open(newer); err != nil {
		t.Fatal(err)
	} else if c, err := z.Total(ctx, "b"); err != nil || c.Objects != 0 {
		t.Fatalf("a later layout: %+v, %v", c, err)
	} else {
		z.Close()
	}
	x, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if c, err := x.Total(ctx, "b"); err != nil || c.Objects != 0 {
		t.Fatalf("kept: %+v, %v", c, err)
	}
	x.Put(ctx, "b", Object{Key: "k", Size: 1, ETag: "e"}, time.Now())
	x.Close()
	y, _ := Open(path) // the same layout: kept
	defer y.Close()
	if c, _ := y.Total(ctx, "b"); c.Objects != 1 {
		t.Fatal("the current layout dropped")
	}
}

// A build counts when a common manifest naming it is verified with the keys now in
// force (any common manifest, without keys); the first by id owns a shared object.
// Only BOMs' entries count, and only those of the bucket asked, certified there.
func TestCertified(t *testing.T) {
	x, _ := open(t)
	now := time.UnixMilli(1_000_000)
	for k, m := range map[string]Manifest{
		"b M/a/x.json":                  {Kind: KindBOM, Builds: []string{"release_a"}, Entries: []Entry{{"el9", "h1", "", ""}, {"el9", "h2", "", ""}}},
		"b M/b/x.json":                  {Kind: KindBOM, Builds: []string{"release_b"}, Entries: []Entry{{"el9", "h1", "", ""}}},
		"b M/c/x.json":                  {Kind: KindBOM, Builds: []string{"release_c"}, Entries: []Entry{{"el10", "h3", "", ""}}},
		"b M/n/x.json":                  {Kind: KindNone, Builds: []string{"release_a"}, Entries: []Entry{{"el9", "h4", "", ""}}},
		"b M/d/x.json":                  {Kind: KindBOM, Builds: []string{"release_d"}, Entries: []Entry{{"el9", "h6", "", ""}}},
		"b M/common-manifest-el9.json":  {Kind: KindCommon, Builds: []string{"release_b", "release_a"}, Keys: "k1", VerifiedBy: "k1"},
		"b M/common-manifest-el10.json": {Kind: KindCommon, Builds: []string{"release_c"}, Keys: "k1"},
		"o M/a/x.json":                  {Kind: KindBOM, Builds: []string{"release_a"}, Entries: []Entry{{"el9", "h5", "", ""}}},
		"o M/common-manifest-el9.json":  {Kind: KindCommon, Builds: []string{"release_d"}, Keys: "k1", VerifiedBy: "k1"},
	} {
		bucket, key, _ := strings.Cut(k, " ")
		m.Key, m.ETag, m.At = key, "e", now
		if err := x.PutManifest(ctx, bucket, m); err != nil {
			t.Fatal(err)
		}
	}
	owner, signed, err := x.Certified(ctx, "b", "k1")
	if err != nil || len(owner) != 2 || owner[[2]string{"el9", "h1"}] != "release_a" || owner[[2]string{"el9", "h2"}] != "release_a" ||
		!signed["release_a"] || !signed["release_b"] || signed["release_c"] {
		t.Fatalf("with k1: %v %v %v", owner, signed, err)
	}
	if owner, signed, _ := x.Certified(ctx, "b", ""); len(owner) != 3 || len(signed) != 0 {
		t.Fatalf("without keys: %v %v", owner, signed)
	}
	if owner, signed, _ := x.Certified(ctx, "b", "k2"); len(owner) != 0 || len(signed) != 0 {
		t.Fatalf("checked with keys no longer in force: %v %v", owner, signed)
	}
}

// Another process reads the service's index as it is, or not at all.
func TestOpenReadOnly(t *testing.T) {
	x, path := open(t)
	x.Put(ctx, "b", Object{Key: "k", Size: 1, ETag: "e"}, time.Now())
	y, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := y.Total(ctx, "b"); c.Objects != 1 {
		t.Fatal("not read")
	}
	if err := y.Put(ctx, "b", Object{Key: "k2", Size: 1, ETag: "e"}, time.Now()); err == nil {
		t.Fatal("written")
	}
	if err := y.Forget(ctx, "b", "k", "e"); err != nil { // left to the service's listing
		t.Fatal(err)
	}
	if err := x.Forget(ctx, "b", "k", "other"); err != nil {
		t.Fatal(err)
	}
	if c, _ := y.Total(ctx, "b"); c.Objects != 1 {
		t.Fatal("forgotten read only, or with another ETag")
	}
	y.Close()
	x.db.Exec(`PRAGMA user_version = 99`)
	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("another layout opened")
	}
	if c, _ := x.Total(ctx, "b"); c.Objects != 1 {
		t.Fatal("the service's index changed")
	}
	if _, err := OpenReadOnly(path + ".none"); err == nil {
		t.Fatal("a missing file opened")
	}
}
