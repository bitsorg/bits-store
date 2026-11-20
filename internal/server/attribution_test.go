// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

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
