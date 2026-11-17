// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// adminToken signs a token with the vectors' admin key ("admin-1"), as bits-console would.
func adminToken(t *testing.T, s *Server, sub string, life time.Duration, caps ...string) string {
	seed := sha256.Sum256([]byte("bits-store test admin key"))
	k := ed25519.NewKeyFromSeed(seed[:])
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	var cs []map[string]string
	for _, c := range caps {
		m, p, _ := strings.Cut(c, " ")
		cs = append(cs, map[string]string{"m": m, "p": p})
	}
	iat := s.now().Unix()
	si := enc(map[string]string{"alg": "EdDSA", "typ": "bits-store+jwt", "kid": "admin-1"}) + "." +
		enc(map[string]any{"iss": s.verifier.Issuer, "aud": s.verifier.Audience, "sub": sub, "grp": "sft",
			"iat": iat, "exp": iat + int64(life/time.Second), "jti": sub + life.String(), "cap": cs})
	return si + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, []byte(si)))
}

func doAdmin(s *Server, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeAdmin(w, r)
	return w
}

// Only an admin key's short token, allowed the path, opens the admin API, and only there.
func TestAdminAuth(t *testing.T) {
	s, good, _ := setup(t)
	withIndex(t, s)
	admin := adminToken(t, s, "admin:alice", 10*time.Minute, "GET /_admin/**")
	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }
	for _, c := range []struct {
		name, method, target string
		hdr                  map[string]string
		code                 int
	}{
		{"summary", "GET", "/_admin/summary", bearer(admin), 200},
		{"head", "HEAD", "/_admin/summary", bearer(admin), 200},
		{"no-token", "GET", "/_admin/summary", nil, 401},
		{"other-scheme", "GET", "/_admin/summary", map[string]string{"Authorization": "Token " + admin}, 401},
		{"cookie-only", "GET", "/_admin/summary", map[string]string{"Cookie": cookieName + "=" + admin}, 401},
		{"user-key", "GET", "/_admin/summary", bearer(good), 401},
		{"long-lived", "GET", "/_admin/summary", bearer(adminToken(t, s, "admin:alice", time.Hour, "GET /_admin/**")), 401},
		{"not-allowed", "GET", "/_admin/summary", bearer(adminToken(t, s, "admin:alice", time.Minute, "GET /_admin/other")), 403},
		{"user-sub", "GET", "/_admin/summary", bearer(adminToken(t, s, "alice", time.Minute, "GET /_admin/**")), 401},
		{"post", "POST", "/_admin/summary", bearer(admin), 405},
		{"unknown", "GET", "/_admin/nothing", bearer(admin), 404},
		{"a-store-path", "GET", "/store/lhcb/x86_64-el10/ab", bearer(admin), 404},
	} {
		if w := doAdmin(s, c.method, c.target, c.hdr); w.Code != c.code {
			t.Errorf("%s: want %d, got %d", c.name, c.code, w.Code)
		}
	}
	// the store's own listener never answers the admin API
	if w := do(s, "GET", "/_admin/summary", bearer(admin)); w.Code != 401 {
		t.Errorf("the admin API on the store's listener: %d", w.Code)
	}
}

// The summary counts each binding's objects from the index: by architecture, those a
// certified build lists, those read lately; a gated binding's by group/architecture.
func TestAdminSummary(t *testing.T) {
	s, m, x, _ := gcSetup(t)
	ctx := context.Background()
	at := s.place["s3"]
	// a BOM of the build the verified common manifest names: hash aa (a, r0-r3) certified
	bom := "MM/release_x-1/a.el9.json"
	m.objs[bom] = []byte(`{"build_id": "release_x-1", "packages": [{"hash": "aa", "effective_architecture": "el9"}]}`)
	x.Put(ctx, at, index.Object{Key: bom, Size: int64(len(m.objs[bom])), ETag: m.etag(bom), Mtime: s.now()}, s.now())
	s.readManifests(ctx)
	x.AddReads(ctx, map[[2]string]index.Read{{at, "TT/el9/store/bb/bb22/b-1-1.el9.tar.gz"}: {N: 2, Last: s.now()},
		{at, "TT/el10/store/dd/dd44/d-1-1.el10.tar.gz"}: {N: 1, Last: s.now().Add(-2 * readLately)}}) // not lately
	s.stores["a0"], s.place["a0"] = s.stores["pub"], at // an anonymous volume first by name, on the same bucket
	sum, err := s.summarize(ctx, s.now())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(sum); !strings.Contains(string(b), `"drift":{"missing":`) || strings.Contains(string(b), `"a0"`) {
		t.Fatalf("%s", b)
	}
	var v *VolumeSummary
	for i := range sum.Volumes {
		if sum.Volumes[i].Volume == "s3" {
			v = &sum.Volumes[i]
		}
	}
	if v == nil || !v.Indexed || v.Listed == nil || v.Drift == nil || v.Objects == 0 || sum.ReadsSince == nil {
		t.Fatalf("%+v", sum)
	}
	var tt *BindingSummary
	var total, bytes int64
	for i := range v.Bindings {
		total, bytes = total+v.Bindings[i].Objects, bytes+v.Bindings[i].Bytes
		if v.Bindings[i].KeyPrefix == "TT" {
			tt = &v.Bindings[i]
		}
	}
	if total != v.Objects || bytes != v.Bytes {
		t.Errorf("the bindings hold %d (%d B) of the bucket's %d (%d B)", total, bytes, v.Objects, v.Bytes)
	}
	by := map[string]int64{}
	for _, a := range tt.By {
		by[a.Name] = a.Objects
	}
	// el9: a, r0-r3 (certified), b, c (young), dist/x, ee/xx55/e; el10: d
	if tt.Objects != 10 || by["el9"] != 9 || by["el10"] != 1 || tt.Certified == nil || tt.Certified.Objects != 5 ||
		tt.ReadLately != 1 || tt.By[0].Name != "el9" {
		t.Fatalf("%+v %+v", tt, tt.Certified)
	}
	for _, b := range v.Bindings {
		if b.Format != "tarballs" && (b.By != nil || b.Certified != nil) {
			t.Errorf("not a tarballs binding, yet split: %+v", b)
		}
	}
	gate(s).Gate = "group"
	x.Put(ctx, at, index.Object{Key: "TT/lhcb/el9/store/ff/ff66/f-1-1.el9.tar.gz", Size: 7, ETag: "f"}, s.now())
	if sum, err = s.summarize(ctx, s.now()); err != nil {
		t.Fatal(err)
	}
	for _, vol := range sum.Volumes {
		for _, b := range vol.Bindings {
			if b.KeyPrefix != "TT" {
				continue
			}
			found := false
			for _, a := range b.By {
				found = found || a.Name == "lhcb/el9" && a.Objects == 1
			}
			if b.Certified != nil || !found {
				t.Fatalf("a gated binding by group: %+v", b)
			}
		}
	}
}
