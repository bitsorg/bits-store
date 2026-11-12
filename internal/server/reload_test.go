// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// reloadConfig is the vectors' issuer and keys with one keyed volume and bindings.
func reloadConfig(t *testing.T, bindings ...Binding) (*Config, string, time.Time) {
	t.Setenv("TEST_AK", "AKIDEXAMPLE")
	t.Setenv("TEST_SK", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	b, err := os.ReadFile("../../testdata/tokens/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &Config{Issuer: v.Issuer, Audience: v.Audience, Keys: v.Keys,
		Volumes: map[string]VolumeConf{"s3": {Endpoint: "https://s3.example.org", Bucket: "bits",
			Region: "us-east-1", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}},
		Bindings: bindings}, v.Cases[0].Token, time.Unix(v.Now, 0)
}

func writeConfig(t *testing.T, path string, c *Config) {
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReloadTakesAGoodConfigAndKeepsTheRunningOneOverABadOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	sources := Binding{Prefix: "/sources/archives", Volume: "s3", KeyPrefix: "SOURCES/cache"}
	c, good, now := reloadConfig(t, sources)
	writeConfig(t, path, c)
	if err := CheckConfig(path); err != nil {
		t.Fatalf("CheckConfig of a good file: %v", err)
	}
	r, _, err := NewReloader(path)
	if err != nil {
		t.Fatal(err)
	}
	s := r.cur.Load()
	s.now = func() time.Time { return now }
	get := func() int {
		w := do(r.cur.Load(), "GET", "/store/lhcb/x86_64-el10-gcc14-opt/ab/h",
			map[string]string{"Authorization": "Bearer " + good})
		return w.Code
	}
	if ok, err := r.Check(); ok || err != nil || get() != 404 {
		t.Fatalf("unchanged file: reloaded %v, %v; GET %d, want 404", ok, err, get())
	}
	running := &fetchJob{done: make(chan struct{})}
	s.fetches.m = map[string]*fetchJob{"failed": {until: now.Add(time.Hour)}, "running": running}
	c.Bindings = append(c.Bindings, Binding{Prefix: "/store/lhcb", Volume: "s3", KeyPrefix: "TARS"})
	writeConfig(t, path, c)
	if ok, err := r.Check(); !ok || err != nil || get() != 302 {
		t.Fatalf("new binding: reloaded %v, %v; GET %d, want 302", ok, err, get())
	}
	if r.cur.Load().uploads != s.uploads || r.cur.Load().fetches != s.fetches {
		t.Fatal("pending uploads or fetches did not carry over")
	}
	if s.fetches.m["failed"] != nil || s.fetches.m["running"] != running {
		t.Fatal("remembered failures kept, or a running fetch dropped")
	}
	c.Bindings = append(c.Bindings, Binding{Prefix: "/store/atlas", Volume: "nowhere"})
	writeConfig(t, path, c)
	if CheckConfig(path) == nil {
		t.Fatal("CheckConfig took a binding to a missing volume")
	}
	if ok, err := r.Check(); ok || err == nil || get() != 302 {
		t.Fatalf("bad file: reloaded %v, %v; GET %d, want the running config (302)", ok, err, get())
	}
	if ok, err := r.Check(); ok || err != nil {
		t.Fatalf("the same bad file again: %v, %v; want it tried once", ok, err)
	}
	// a trusted key removed: a token already verified and cached stops working
	c.Bindings = c.Bindings[:len(c.Bindings)-1]
	c.Keys = map[string]KeyConfig{}
	for kid, k := range reloadKeys(t) {
		if kid != "test-1" {
			c.Keys[kid] = k
		}
	}
	writeConfig(t, path, c)
	if ok, err := r.Check(); !ok || err != nil || get() != 401 {
		t.Fatalf("key removed: reloaded %v, %v; GET %d, want 401", ok, err, get())
	}
}

func reloadKeys(t *testing.T) map[string]KeyConfig {
	c, _, _ := reloadConfig(t)
	return c.Keys
}

func TestAnExpiredUploadOfARemovedVolumeIsDropped(t *testing.T) {
	ut, now := &uploadTable{}, time.Now()
	ut.add("old", &upload{volume: "gone", staging: "STAGING/x", sub: "a", expires: now.Add(-time.Second)},
		now.Add(-time.Minute), nil)
	if !ut.add("new", &upload{volume: "s3", sub: "a", expires: now.Add(time.Minute)}, now, map[string]objectStore{}) {
		t.Fatal("add refused")
	}
	time.Sleep(50 * time.Millisecond) // a cleanup on a nil store would panic here
	if ut.get("old") != nil {
		t.Fatal("the expired upload stayed")
	}
}

func TestALeaseOutlivesARenamedVolume(t *testing.T) {
	c, _, now := reloadConfig(t, Binding{Prefix: "/store", Volume: "s3", KeyPrefix: "TARS"})
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if !a.uploads.lease(a.place["s3"], "TARS/x", now) {
		t.Fatal("no lease")
	}
	a.uploads.hold(a.place["s3"], "TARS/x", now.Add(time.Minute)) // a copy that may still land
	c.Volumes["s3b"], c.Bindings[0].Volume = c.Volumes["s3"], "s3b"
	delete(c.Volumes, "s3")
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	b.uploads = a.uploads
	if b.uploads.lease(b.place["s3b"], "TARS/x", now) {
		t.Fatal("the same bucket under a new volume name got the key while it was held")
	}
}
