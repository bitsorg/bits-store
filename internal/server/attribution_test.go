// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// A read by hash names who uploaded the build, when the index knows it.
func TestTarballSaysItsWriter(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	withIndex(t, s)
	auth := map[string]string{"Authorization": "Bearer " + tok}
	data := []byte("tarball")
	st := startNamed(t, s, tok, tarName, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	if w := do(s, "HEAD", tarPath, auth); w.Code != 302 || w.Header().Get("Bits-Object-By") != "alice" {
		t.Fatalf("uploaded by alice: %d %v", w.Code, w.Header())
	}
	// written outside the service (a listing found it): no writer
	key := tarDir + "/" + tarName
	s.index.Put(context.Background(), s.place["s3"], index.Object{Key: key, Size: 7, ETag: m.etag(key), Mtime: s.now()}, s.now())
	if w := do(s, "HEAD", tarPath, auth); w.Code != 302 || w.Header().Values("Bits-Object-By") != nil {
		t.Fatalf("not known: %d %v", w.Code, w.Header())
	}
}

// The admin API lists the uploads of people, not those of builds or fills.
func TestAdminObjectsByPeople(t *testing.T) {
	s, _, x, _ := gcSetup(t)
	at, ctx := s.place["s3"], context.Background()
	for k, o := range map[string][2]string{"TT/a/store/aa/aaaa/a.tar.gz": {index.OriginUpload, "alice"},
		"TT/a/store/bb/bbbb/b.tar.gz": {index.OriginUpload, "build:42"},
		"TT/a/store/cc/cccc/c.tar.gz": {index.OriginFill, "bob"}, "TT/a/store/dd/dddd/d.tar.gz": {"", ""}} {
		x.Put(ctx, at, index.Object{Key: k, Size: 1, ETag: "e", Mtime: s.now(), Origin: o[0], Sub: o[1]}, s.now())
	}
	auth := map[string]string{"Authorization": "Bearer " + adminToken(t, s, "admin:carol", time.Minute, "GET /_admin/**")}
	w := doAdmin(s, "GET", "/_admin/objects?binding=/store/lhcb/x86_64-el10-gcc14-opt/t&under=a&by=people", auth)
	var a struct{ Objects []ObjectRow }
	if err := json.Unmarshal(w.Body.Bytes(), &a); w.Code != 200 || err != nil || len(a.Objects) != 1 || a.Objects[0].By != "alice" {
		t.Fatalf("by=people: %d %s", w.Code, w.Body)
	}
	if w := doAdmin(s, "GET", "/_admin/objects?binding=/store/lhcb/x86_64-el10-gcc14-opt/t&by=builds", auth); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "by") {
		t.Fatalf("by=builds: %d %s", w.Code, w.Body)
	}
}
