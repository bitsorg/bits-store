// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
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

// Searching a binding: every object once across pages, narrowed by text, folder,
// verdict, kind and date; the collection's verdict on each package.
func TestAdminObjects(t *testing.T) {
	s, m, x, _ := gcSetup(t)
	ctx := context.Background()
	at := s.place["s3"]
	bom := "MM/release_x-1/a.el9.json"
	m.objs[bom] = []byte(`{"build_id": "release_x-1", "packages": [{"hash": "aa", "effective_architecture": "el9"}]}`)
	x.Put(ctx, at, index.Object{Key: bom, Size: int64(len(m.objs[bom])), ETag: m.etag(bom), Mtime: s.now()}, s.now())
	s.readManifests(ctx)
	auth := map[string]string{"Authorization": "Bearer " + adminToken(t, s, "admin:alice", time.Minute, "GET /_admin/**")}
	tars, mans := "/store/lhcb/x86_64-el10-gcc14-opt/t", "/store/lhcb/x86_64-el10-gcc14-opt/m"
	get := func(code int, query string) (rows []ObjectRow, next string) {
		t.Helper()
		w := doAdmin(s, "GET", "/_admin/objects?"+query, auth)
		if w.Code != code {
			t.Fatalf("%s: want %d, got %d %s", query, code, w.Code, w.Body)
		}
		var a struct {
			Objects []ObjectRow
			Next    string
		}
		if code == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
				t.Fatal(err)
			}
		}
		return a.Objects, a.Next
	}
	keys := func(rows []ObjectRow) string {
		var k []string
		for _, r := range rows {
			k = append(k, strings.TrimPrefix(r.Key, "TT/"))
		}
		return strings.Join(k, " ")
	}
	all, next := get(200, "binding="+url.QueryEscape(tars))
	verdict := map[string]string{}
	for _, r := range all {
		verdict[strings.TrimPrefix(r.Key, "TT/")] = r.Kept
	}
	if len(all) != 10 || next != "" || verdict["el9/store/aa/aa/a-1-1.el9.tar.gz"] != WhyListed ||
		verdict["el9/store/bb/bb22/b-1-1.el9.tar.gz"] != WhyNewest || verdict["el9/store/cc/cc33/c-1-1.el9.tar.gz"] != WhyYoung ||
		verdict["el10/store/dd/dd44/d-1-1.el10.tar.gz"] != WhyUncert || verdict["el9/dist/x"] != WhyOther {
		t.Fatalf("%v %q", verdict, next)
	}
	for _, r := range all {
		if strings.HasSuffix(r.Key, "/b-1-1.el9.tar.gz") && (r.Arch != "el9" || r.Hash != "bb22" || r.File != "b-1-1.el9.tar.gz") {
			t.Fatalf("not parsed: %+v", r)
		}
	}
	var paged []ObjectRow
	for after := ""; ; {
		rows, n := get(200, "limit=3&binding="+url.QueryEscape(tars)+"&after="+url.QueryEscape(after))
		paged = append(paged, rows...)
		if n == "" {
			break
		}
		after = n
	}
	if keys(paged) != keys(all) {
		t.Fatalf("pages:\n%s\nall:\n%s", keys(paged), keys(all))
	}
	scan := searchScan
	defer func() { searchScan = scan }()
	searchScan = 2 // a search that looks at 2 rows: young ones found across answers
	var young []ObjectRow
	for after, n := "", 0; n < 10; n++ {
		rows, next := get(200, "kept=young&binding="+url.QueryEscape(tars)+"&after="+url.QueryEscape(after))
		young = append(young, rows...)
		if next == "" {
			break
		}
		after = next
	}
	searchScan = scan
	if keys(young) != "el9/store/cc/cc33/c-1-1.el9.tar.gz" {
		t.Fatalf("scanned in parts: %q", keys(young))
	}
	for query, want := range map[string]string{
		"q=B-1-1":          "el9/store/bb/bb22/b-1-1.el9.tar.gz",
		"q=%25":            "",
		"kept=young":       "el9/store/cc/cc33/c-1-1.el9.tar.gz",
		"under=el10":       "el10/store/dd/dd44/d-1-1.el10.tar.gz",
		"under=el9/dist":   "el9/dist/x",
		"since=2100-01-01": "",
	} {
		if rows, _ := get(200, query+"&binding="+url.QueryEscape(tars)); keys(rows) != want {
			t.Errorf("%s: %q", query, keys(rows))
		}
	}
	before := "before=" + url.QueryEscape(s.now().Add(-2*time.Hour).Format(time.RFC3339)) + "&binding=" + url.QueryEscape(tars)
	if rows, _ := get(200, before); len(rows) != 9 || strings.Contains(keys(rows), "c-1-1") {
		t.Errorf("before: %q", keys(rows))
	}
	if rows, _ := get(200, "kind=common&binding="+url.QueryEscape(mans)); keys(rows) != "MM/common-manifest-el9.json" {
		t.Errorf("common manifests: %q", keys(rows))
	}
	if rows, _ := get(200, "kind=bom&binding="+url.QueryEscape(mans)); keys(rows) != bom {
		t.Errorf("BOMs: %q", keys(rows))
	}
	for _, query := range []string{"kind=bom&binding=" + url.QueryEscape(tars), "kept=young&binding=" + url.QueryEscape(mans),
		"limit=0&binding=" + url.QueryEscape(tars), "limit=501&binding=" + url.QueryEscape(tars),
		"under=../x&binding=" + url.QueryEscape(tars), "after=MM/x&binding=" + url.QueryEscape(tars),
		"since=yesterday&binding=" + url.QueryEscape(tars), "kept=gone&binding=" + url.QueryEscape(tars)} {
		get(400, query)
	}
	if rows, _ := get(200, "kind=none&binding="+url.QueryEscape(mans)); keys(rows) != "" {
		t.Errorf("kind none: %q", keys(rows))
	}
	gone, cancel := context.WithCancel(ctx) // a plan for verdicts outlives its request
	cancel()
	s.keptBy = keptCache{}
	if why, err := s.kept(gone, at); err != nil || why["TT/el9/store/cc/cc33/c-1-1.el9.tar.gz"] != WhyYoung {
		t.Errorf("verdicts for a request given up: %v %v", why, err)
	}
	if why, err := s.kept(ctx, s.place["pub"]); why != nil || err != nil {
		t.Errorf("a bucket without packages: %v %v", why, err)
	}
	x.Put(ctx, at, index.Object{Key: "TT/el9/Über-README", Size: 1, ETag: "u"}, s.now())
	if rows, _ := get(200, "q="+url.QueryEscape("über-readme")+"&binding="+url.QueryEscape(tars)); keys(rows) != "el9/Über-README" {
		t.Errorf("any case: %q", keys(rows))
	}
	get(404, "binding=/nowhere")
	only := map[string]string{"Authorization": "Bearer " + adminToken(t, s, "admin:bob", time.Minute, "GET /_admin/summary")}
	if w := doAdmin(s, "GET", "/_admin/objects?binding="+url.QueryEscape(tars), only); w.Code != 403 {
		t.Errorf("a token for the summary alone: %d", w.Code)
	}
}

// One object: the index's row, the manifests listing a package, a manifest's
// builds, and the bucket's metadata (unknown when the bucket does not answer).
func TestAdminObject(t *testing.T) {
	s, m, x, _ := gcSetup(t)
	ctx := context.Background()
	bom := "MM/release_x-1/a.el9.json"
	m.objs[bom] = []byte(`{"build_id": "release_x-1", "packages": [{"hash": "aa", "effective_architecture": "el9"}]}`)
	x.Put(ctx, s.place["s3"], index.Object{Key: bom, Size: int64(len(m.objs[bom])), ETag: m.etag(bom), Mtime: s.now()}, s.now())
	s.readManifests(ctx)
	auth := map[string]string{"Authorization": "Bearer " + adminToken(t, s, "admin:alice", time.Minute, "GET /_admin/**")}
	tars, mans := "/store/lhcb/x86_64-el10-gcc14-opt/t", "/store/lhcb/x86_64-el10-gcc14-opt/m"
	get := func(code int, binding, key string) ObjectDetail {
		t.Helper()
		w := doAdmin(s, "GET", "/_admin/object?binding="+url.QueryEscape(binding)+"&key="+url.QueryEscape(key), auth)
		var d ObjectDetail
		if w.Code != code || code == 200 && json.Unmarshal(w.Body.Bytes(), &d) != nil {
			t.Fatalf("%s: want %d, got %d %s", key, code, w.Code, w.Body)
		}
		return d
	}
	a := "TT/el9/store/aa/aa/a-1-1.el9.tar.gz"
	m.meta[a] = map[string]string{"bits-group": "lhcb"}
	d := get(200, tars, a)
	listed := map[string]index.Listing{}
	for _, l := range d.ListedBy {
		listed[l.Key] = l
	}
	if d.Kept != WhyListed || d.Arch != "el9" || d.Hash != "aa" || d.InBucket == nil || !*d.InBucket || d.Meta["bits-group"] != "lhcb" ||
		fmt.Sprint(listed[bom]) != fmt.Sprint(index.Listing{Key: bom, Kind: index.KindBOM, Builds: []string{"release_x-1"}}) ||
		fmt.Sprint(listed["MM/common-manifest-el9.json"]) != fmt.Sprint(index.Listing{Key: "MM/common-manifest-el9.json",
			Kind: index.KindCommon, Builds: []string{"release_x-1"}, Verified: true}) || len(d.ListedBy) != 2 {
		t.Fatalf("%+v", d)
	}
	keys := s.manifestKeys
	s.manifestKeys = index.Keys{} // verified by no key in force now
	for _, l := range get(200, tars, a).ListedBy {
		if l.Verified {
			t.Errorf("verified without manifest_keys: %+v", l)
		}
	}
	s.manifestKeys = keys
	if d := get(200, mans, "MM/common-manifest-el9.json"); d.Kind != index.KindCommon || strings.Join(d.Builds, " ") != "release_x-1" || d.ListedBy != nil {
		t.Fatalf("a common manifest: %+v", d)
	}
	delete(m.objs, a)
	if d := get(200, tars, a); d.InBucket == nil || *d.InBucket {
		t.Fatalf("gone from the bucket: %+v", d.InBucket)
	}
	m.statFails = a
	if d := get(200, tars, a); d.InBucket != nil || d.Kept != WhyListed {
		t.Fatalf("a bucket that does not answer: %+v", d)
	}
	get(400, tars, "MM/common-manifest-el9.json")
	get(400, tars, "")
	get(404, tars, "TT/el9/store/zz/zz/none")
	get(404, "/nowhere", a)
}
