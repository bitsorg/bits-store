// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

var ctx = context.Background()

func open(t *testing.T) (*Index, string) {
	path := filepath.Join(t.TempDir(), "index.db")
	x, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	return x, path
}

func listing(objs ...Object) func(func(Object) error) error {
	return func(add func(Object) error) error {
		for _, o := range objs {
			if err := add(o); err != nil {
				return err
			}
		}
		return nil
	}
}

func has(t *testing.T, x *Index, bucket, key string) bool {
	_, ok, err := x.Get(ctx, bucket, key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestVerifyRepairsAndReports(t *testing.T) {
	x, _ := open(t)
	t0 := time.UnixMilli(1_000_000)
	x.Put(ctx, "b", Object{Key: "same", Size: 1, ETag: "e1", SHA256: "s1"}, t0)
	x.Put(ctx, "b", Object{Key: "changed", Size: 2, ETag: "e2", SHA256: "s2"}, t0)
	x.Put(ctx, "b", Object{Key: "gone", Size: 3, ETag: "e3"}, t0)
	x.Put(ctx, "other", Object{Key: "gone", Size: 3, ETag: "e3"}, t0) // another bucket's
	if _, _, ok, _ := x.Verified(ctx, "b"); ok {
		t.Fatal("verified before any listing")
	}
	start := t0.Add(time.Hour)
	d, err := x.Verify(ctx, "b", start, listing(
		Object{Key: "same", Size: 1, ETag: "e1"},
		Object{Key: "changed", Size: 2, ETag: "e2b"},
		Object{Key: "new", Size: 4, ETag: "e4"}))
	if err != nil || d != (Drift{Missing: 1, Changed: 1, Extra: 1}) {
		t.Fatalf("drift %+v, %v", d, err)
	}
	if has(t, x, "b", "gone") || !has(t, x, "b", "new") || !has(t, x, "other", "gone") {
		t.Fatal("not repaired, or another bucket touched")
	}
	if o, _, _ := x.Get(ctx, "b", "same"); o.SHA256 != "s1" {
		t.Fatal("an unchanged object lost its sha256")
	}
	if o, _, _ := x.Get(ctx, "b", "changed"); o.SHA256 != "" || o.ETag != "e2b" {
		t.Fatalf("a changed object kept its old sha256: %+v", o)
	}
	at, got, ok, err := x.Verified(ctx, "b")
	if !ok || err != nil || !at.Equal(start) || got != d {
		t.Fatalf("verified %v %+v %v %v", at, got, ok, err)
	}
	if d, _ := x.Verify(ctx, "b", start.Add(time.Hour), listing(
		Object{Key: "same", Size: 1, ETag: "e1"}, Object{Key: "changed", Size: 2, ETag: "e2b"},
		Object{Key: "new", Size: 4, ETag: "e4"})); d != (Drift{}) {
		t.Fatalf("a second listing of the same bucket: %+v", d)
	}
}

// What the service writes while a listing runs is kept, though the listing missed it.
func TestAWriteDuringTheListingIsKept(t *testing.T) {
	x, _ := open(t)
	start := time.UnixMilli(2_000_000)
	d, err := x.Verify(ctx, "b", start, func(add func(Object) error) error {
		add(Object{Key: "listed", Size: 1, ETag: "e"})
		x.Put(ctx, "b", Object{Key: "written", Size: 1, ETag: "e"}, start.Add(time.Second))
		return nil
	})
	if err != nil || d.Extra != 0 || !has(t, x, "b", "written") {
		t.Fatalf("drift %+v, %v", d, err)
	}
	// listed before the service wrote it again, flushed after: the service's row stands
	start = start.Add(time.Hour)
	d, err = x.Verify(ctx, "b", start, func(add func(Object) error) error {
		add(Object{Key: "written", Size: 1, ETag: "old"})
		x.Put(ctx, "b", Object{Key: "written", Size: 2, ETag: "new", SHA256: "s"}, start.Add(time.Second))
		return nil
	})
	if o, _, _ := x.Get(ctx, "b", "written"); err != nil || d != (Drift{Extra: 1}) || o.ETag != "new" || o.SHA256 != "s" {
		t.Fatalf("drift %+v, %v; row %+v", d, err, o)
	}
}

func TestAFailedListingRemovesNothing(t *testing.T) {
	x, path := open(t)
	t0 := time.UnixMilli(1_000_000)
	x.Put(ctx, "b", Object{Key: "kept", Size: 1, ETag: "e"}, t0)
	boom := errors.New("listing broke")
	_, err := x.Verify(ctx, "b", t0.Add(time.Hour), func(add func(Object) error) error {
		add(Object{Key: "first", Size: 1, ETag: "e"})
		return boom
	})
	if !errors.Is(err, boom) || !has(t, x, "b", "kept") {
		t.Fatalf("%v, or a row went", err)
	}
	if _, _, ok, _ := x.Verified(ctx, "b"); ok {
		t.Fatal("a failed listing counted as a verify")
	}
	// more than one batch, and the index kept on disk
	var objs []Object
	for i := range batch + 5 {
		objs = append(objs, Object{Key: string(rune('a'+i%26)) + time.Duration(i).String(), Size: 1, ETag: "e"})
	}
	if d, err := x.Verify(ctx, "b", t0.Add(2*time.Hour), listing(objs...)); err != nil || d.Missing != int64(len(objs)) || d.Extra != 1 {
		t.Fatalf("drift %+v, %v", d, err)
	}
	x.Close()
	y, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer y.Close()
	if !has(t, y, "b", objs[batch].Key) {
		t.Fatal("not kept on disk")
	}
}

func TestAFailedPutIsCounted(t *testing.T) {
	x, _ := open(t)
	x.Close()
	if err := x.Put(ctx, "b", Object{Key: "k"}, time.Now()); err == nil || x.Errors() != 1 {
		t.Fatalf("%v, %d", err, x.Errors())
	}
}

func TestTotal(t *testing.T) {
	x, _ := open(t)
	now := time.UnixMilli(1_000_000)
	for k, n := range map[string]int64{
		"TARS/el9/store/ab/abc/a.tar.gz": 10, "TARS/el9/dist/x": 1, "TARS/el10/store/cd/cde/b.tar.gz": 5,
		"TARS/top": 2, "TARS//odd": 7, "TARSX/el9/y": 100, "MANIFESTS/m": 1000,
	} {
		x.Put(ctx, "b", Object{Key: k, Size: n, ETag: "e"}, now)
	}
	x.Put(ctx, "other", Object{Key: "TARS/el9/z", Size: 1, ETag: "e"}, now)
	if c, err := x.Total(ctx, "b"); err != nil || c != (Count{Objects: 7, Bytes: 1125}) {
		t.Fatalf("total %+v, %v", c, err)
	}
	if c, _ := x.Total(ctx, "empty"); c != (Count{}) {
		t.Fatalf("an empty bucket: %+v", c)
	}
}

// An index of layout 4 to 6 gains the columns added since and stays: not listed
// again; one half migrated before (a column there already) too.
func TestFromOlderLayouts(t *testing.T) {
	for _, from := range []string{"4", "4 and reads", "5", "5 and grp", "6"} {
		path := filepath.Join(t.TempDir(), "index.db")
		db, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{`CREATE TABLE objects (bucket TEXT NOT NULL, key TEXT NOT NULL, size INTEGER NOT NULL,
			etag TEXT NOT NULL, mtime INTEGER NOT NULL, sha256 TEXT, seen INTEGER NOT NULL, PRIMARY KEY (bucket, key)) WITHOUT ROWID`,
			`INSERT INTO objects VALUES ('b', 'k', 1, 'e', 0, NULL, 0)`, `PRAGMA user_version = 4`} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		var alter []string
		switch from {
		case "4 and reads":
			alter = []string{"reads INTEGER NOT NULL DEFAULT 0"}
		case "6":
			alter = []string{"grp TEXT NOT NULL DEFAULT ''", "reads INTEGER NOT NULL DEFAULT 0", "read_at INTEGER NOT NULL DEFAULT 0", "6"}
		case "5 and grp":
			alter = []string{"grp TEXT NOT NULL DEFAULT ''"}
			fallthrough
		case "5":
			alter = append(alter, "reads INTEGER NOT NULL DEFAULT 0", "read_at INTEGER NOT NULL DEFAULT 0", "5")
		}
		for _, c := range alter {
			q := "ALTER TABLE objects ADD COLUMN " + c
			if c == "5" || c == "6" {
				q = `PRAGMA user_version = ` + c
			}
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		db.Close()
		x, err := Open(path)
		if err != nil {
			t.Fatalf("from %s: %v", from, err)
		}
		if c, _ := x.Total(ctx, "b"); c.Objects != 1 {
			t.Fatal("dropped")
		}
		if since, err := x.ReadsSince(ctx); err != nil || time.Since(since) > time.Minute {
			t.Fatalf("reads since %v, %v", since, err)
		}
		x.AddReads(ctx, map[[2]string]Read{{"b", "k"}: {N: 2, Last: time.UnixMilli(5)}, {"b", "none"}: {N: 1}})
		if err := x.Put(ctx, "b", Object{Key: "w", Size: 1, ETag: "e", Grp: "lhcb", Origin: OriginUpload, Sub: "alice"}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if o, _, err := x.Get(ctx, "b", "w"); err != nil || o.Grp != "lhcb" || o.Origin != OriginUpload || o.Sub != "alice" {
			t.Fatalf("from %s: the writer's group not kept: %+v %v", from, o, err)
		}
		x.Close()
		y, err := OpenReadOnly(path)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		if err := y.Each(ctx, "b", "", func(o Object) {
			if n++; o.Key == "k" && (o.Reads != 2 || o.ReadAt.UnixMilli() != 5 || o.Grp != "") {
				t.Fatalf("from %s: %+v", from, o)
			}
		}); err != nil || n != 2 {
			t.Fatalf("from %s: %d rows, %v", from, n, err)
		}
		y.Close()
	}
}
