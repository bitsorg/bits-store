// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// The store's packages by the certified build first listing them: verified common
// manifests count when there are manifest keys, every one without.
func TestMetricsByBuild(t *testing.T) {
	s, _, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	withIndex(t, s)
	ctx := context.Background()
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/manifests/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	bom := func(build, arch string, hashes ...string) []byte {
		var p []string
		for _, h := range hashes {
			p = append(p, `{"hash": "`+h+`", "effective_architecture": "`+arch+`"}`)
		}
		return []byte(`{"build_id": "` + build + `", "packages": [` + strings.Join(p, ",") + `]}`)
	}
	m.objs["TT/el9/store/aa/aa11/a-1-1.el9.tar.gz"] = []byte("1234567890")
	m.objs["TT/el9/store/bb/bb22/b-1-1.el9.tar.gz"] = []byte("12345")
	m.objs["TT/el10/store/cc/cc33/c-1-1.el10.tar.gz"] = []byte("123")
	m.objs["TT/el10/other"] = []byte("1")
	m.objs["TT/el9/dist/aa/aa11/x"] = []byte("1")                         // not in the store tree: no build
	m.objs["TT/top"], m.objs["TT//odd"] = []byte("12"), []byte("1234567") // as bits' store-stats: "top", none
	m.objs["MM/release_x-1/a.el9.json"] = bom("release_x-1", "el9", "aa11")
	m.objs["MM/release_y-1/a.el9.json"] = bom("release_y-1", "el9", "aa11")   // later by id: not the owner
	m.objs["MM/release_u-1/a.el9.json"] = bom("release_u-1", "el9", "bb22")   // never certified
	m.objs["MM/release_z-1/a.el10.json"] = bom("release_z-1", "el10", "cc33") // by an unsigned common manifest
	m.objs["MM/common-manifest-el9.json"] = read("common-manifest-el9.json")  // sources: release_x-1, signed
	m.objs["MM/common-manifest-el9.json.sig"] = read("common-manifest-el9.json.sig")
	m.objs["MM/common-manifest-el10.json"] = []byte(`{"kind": "common-manifest", "sources": ["release_z-1", "release_y-1"], "packages": []}`)
	clock := now
	s.now = func() time.Time { return clock }
	scrape := func() string {
		clock = clock.Add(metricsEvery)
		s.verifyDue(ctx, map[string]time.Time{})
		s.readManifests(ctx)
		w := do(s, "GET", "/metrics", nil)
		if w.Code != 200 {
			t.Fatalf("metrics: %d", w.Code)
		}
		return w.Body.String()
	}
	has := func(body string, want ...string) {
		for _, l := range want {
			if !strings.Contains(body, "\nbits_store_manifest_bytes{volume=\"s3\","+l+"\n") {
				t.Fatalf("no %s in:\n%s", l, body)
			}
		}
	}
	body := scrape() // no keys: every common manifest counts, none signed
	has(body, `manifest="(uncertified)",arch="el10",signed="0"} 1`, `manifest="(uncertified)",arch="el9",signed="0"} 6`,
		`manifest="release_x-1",arch="el9",signed="0"} 10`, `manifest="release_z-1",arch="el10",signed="0"} 3`)
	keys, err := index.ParseKeys([]string{string(read("test-key.pem"))})
	if err != nil {
		t.Fatal(err)
	}
	s.manifestKeys = keys // only the verified one counts now
	body = scrape()
	has(body, `manifest="(uncertified)",arch="el10",signed="0"} 4`, `manifest="(uncertified)",arch="el9",signed="0"} 6`,
		`manifest="release_x-1",arch="el9",signed="1"} 10`)
	for _, l := range []string{`bits_store_bytes{volume="s3",arch="el9"} 16`, `bits_store_bytes{volume="s3",arch="el10"} 4`,
		`bits_store_bytes{volume="s3",arch="top"} 2`, `bits_store_objects{volume="s3",arch="el9"} 3`,
		`bits_store_manifest_objects{volume="s3",manifest="release_x-1",arch="el9",signed="1"} 1`} {
		if !strings.Contains(body, "\n"+l+"\n") { // the two splits add up to the same
			t.Fatalf("no %s in:\n%s", l, body)
		}
	}
	if strings.Contains(body, "release_z-1") || strings.Contains(body, "release_y-1") {
		t.Fatalf("an unverified common manifest counted:\n%s", body)
	}
}
