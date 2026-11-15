// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
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
