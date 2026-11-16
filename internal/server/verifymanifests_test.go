// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// Common manifests are verified with the manifest keys, again when their .sig or
// the keys change; without keys none is (and every one is read).
func TestCommonManifestsVerified(t *testing.T) {
	s, _, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	x := withIndex(t, s)
	ctx := context.Background()
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/manifests/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	const key = "MM/common-manifest-el9.json"
	m.objs[key], m.objs[key+".sig"] = read("common-manifest-el9.json"), read("common-manifest-el9.json.sig")
	keys, err := index.ParseKeys([]string{string(read("test-key.pem"))})
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	s.now = func() time.Time { return clock }
	tick := func(listed bool) string {
		if listed {
			clock = clock.Add(s.verifyEvery)
			s.verifyDue(ctx, map[string]time.Time{})
		}
		s.readManifests(ctx)
		by, err := x.VerifiedBy(ctx, s.place["s3"], key)
		if err != nil {
			t.Fatal(err)
		}
		return by
	}
	if by := tick(true); by != "" {
		t.Fatalf("verified without keys: %q", by)
	}
	if k, _, _ := x.Builds(ctx, s.place["s3"], key); k != index.KindCommon {
		t.Fatalf("not read without keys: %q", k)
	}
	s.manifestKeys = keys // keys added (a reload): checked again
	if by := tick(false); by != "56475aa75463474c" {
		t.Fatalf("not verified: %q", by)
	}
	got := m.got
	if tick(false); m.got != got {
		t.Fatal("checked again unchanged")
	}
	m.objs[key+".sig"] = []byte(`{"alg": "ed25519", "key_id": "56475aa75463474c", "sig": "AAAA"}`) // replaced
	if by := tick(true); by != "" {
		t.Fatalf("a bad .sig verified: %q", by)
	}
	m.objs[key+".sig"] = read("common-manifest-el9.json.sig")
	if by := tick(true); by != "56475aa75463474c" {
		t.Fatalf("not verified again: %q", by)
	}
	delete(m.objs, key+".sig") // gone: not verified
	if by := tick(true); by != "" {
		t.Fatalf("verified without a .sig: %q", by)
	}
	m.objs[key+".sig"] = read("common-manifest-el9.json.sig") // back, but unreadable: nothing of it for now
	m.getFailsOn = key + ".sig"
	if tick(true); kindOf(t, x, s.place["s3"], key) != index.KindUnread {
		t.Fatal("not unread")
	}
	if _, builds, _ := x.Builds(ctx, s.place["s3"], key); builds != nil {
		t.Fatalf("an unread manifest's sources kept: %v", builds)
	}
	m.getFailsOn = ""
	clock = clock.Add(index.RetryUnread)
	if by := tick(false); by != "56475aa75463474c" {
		t.Fatalf("not verified after the retry: %q", by)
	}
	s.manifestKeys = nil // keys removed (a reload): none verified
	if by := tick(false); by != "" {
		t.Fatalf("verified without keys: %q", by)
	}
}

func kindOf(t *testing.T, x *index.Index, bucket, key string) string {
	k, _, err := x.Builds(context.Background(), bucket, key)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
