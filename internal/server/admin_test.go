// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	// The most read and the newest first: the first rows, without next.
	x.AddReads(ctx, map[[2]string]index.Read{{at, "TT/el9/store/cc/cc33/c-1-1.el9.tar.gz"}: {N: 5, Last: s.now()},
		{at, "TT/el9/dist/x"}: {N: 2, Last: s.now()}})
	if rows, next := get(200, "order=reads&limit=2&binding="+url.QueryEscape(tars)); keys(rows) != "el9/store/cc/cc33/c-1-1.el9.tar.gz el9/dist/x" || next != "" {
		t.Errorf("most read: %q %q", keys(rows), next)
	}
	newest := all[0]
	for _, r := range all {
		if r.Written.After(newest.Written) {
			newest = r
		}
	}
	if rows, _ := get(200, "order=written&limit=1&binding="+url.QueryEscape(tars)); len(rows) != 1 || !rows[0].Written.Equal(newest.Written) {
		t.Errorf("newest first: %q, want written %v", keys(rows), newest.Written)
	}
	get(400, "order=size&binding="+url.QueryEscape(tars))
	get(400, "order=reads&after="+url.QueryEscape("TT/el9")+"&binding="+url.QueryEscape(tars))
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

// The access view: the configuration in force, key ids and signers without the keys.
func TestAdminAccess(t *testing.T) {
	s, _, _ := setup(t)
	auth := map[string]string{"Authorization": "Bearer " + adminToken(t, s, "admin:alice", time.Minute, "GET /_admin/**")}
	w := doAdmin(s, "GET", "/_admin/access", auth)
	var a Access
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &a) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	signers := map[string]string{}
	for _, k := range a.Keys {
		signers[k.ID] = k.Signer
	}
	if signers["test-1"] != "user" || signers["build-1"] != "build" || signers["admin-1"] != "admin" ||
		a.RestrictedSign != "" || a.MaxLifetime != "168h" || a.PerSubject != 100 {
		t.Fatalf("%s", w.Body)
	}
	for _, secret := range []string{`"x"`, "TEST_AK", "TEST_SK", "key_env", "region", "site_"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("%s in %s", secret, w.Body)
		}
	}
	for i, b := range a.Bindings {
		if i > 0 && a.Bindings[i-1].Prefix > b.Prefix {
			t.Fatalf("not by prefix: %v", a.Bindings)
		}
	}
	vols := map[string]bool{}
	for _, v := range a.Volumes {
		vols[v.Name] = v.Keys
	}
	if !vols["s3"] || vols["pub"] {
		t.Fatalf("volumes: %v", a.Volumes)
	}
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	deny := "sha256:" + strings.Repeat("ab", 32)
	g, err := New(&Config{Issuer: "i", Audience: "a", Keys: map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
		Volumes: map[string]VolumeConf{"p": {Endpoint: "https://s3.example.org", Bucket: "private", Region: "r",
			AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}},
		Bindings: []Binding{{Prefix: "/restricted", Volume: "p", KeyPrefix: "TARS", Format: "tarballs", Gate: "group",
			Readers: map[string][]string{"sft": {"lhcb"}}, Deny: []string{deny}}},
		RestrictedSigner: SignerConf{AgentSocket: "/run/agent.sock", Route: "r", Host: "signer", Prefix: "/sign/r"}})
	if err != nil {
		t.Fatal(err)
	}
	b := g.access.Bindings[0]
	if b.Gate != "group" || len(b.Readers["sft"]) != 1 || b.Readers["sft"][0] != "lhcb" || len(b.Deny) != 1 || b.Deny[0] != deny ||
		g.access.RestrictedSign != "r" || g.access.Volumes[0].Bucket != "private" {
		t.Fatalf("%+v", g.access)
	}
	b.Readers["sft"][0] = "atlas" // the view is a copy
	if g.bindings[0].Readers["sft"][0] != "lhcb" {
		t.Fatal("the view shares the running bindings")
	}
	// a reload shows the new configuration
	path := filepath.Join(t.TempDir(), "config.json")
	c, _, _ := reloadConfig(t, Binding{Prefix: "/sources/archives", Volume: "s3", KeyPrefix: "SOURCES/cache"})
	writeConfig(t, path, c)
	r, _, err := NewReloader(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Bindings = append(c.Bindings, Binding{Prefix: "/store", Volume: "s3", KeyPrefix: "TARS", Format: "tarballs"})
	writeConfig(t, path, c)
	if ok, err := r.Check(); !ok || err != nil || len(r.cur.Load().access.Bindings) != 2 {
		t.Fatalf("reloaded: %v %v %+v", ok, err, r.cur.Load().access.Bindings)
	}
}

// An admin withdraws a gated binding's build (PUT, with why), kept in the file beside
// the index: reads find none from then on, until the withdrawal is lifted.
func TestAdminWithdraws(t *testing.T) {
	s, m, tok := gated(t)
	file := filepath.Join(t.TempDir(), "withdrawn.json")
	var err error
	if s.withdrawn, err = openWithdrawals(file); err != nil {
		t.Fatal(err)
	}
	data := []byte("tarball")
	sum := sha256.Sum256(data)
	sha := "sha256:" + hex.EncodeToString(sum[:])
	m.objs[filed("lhcb")], m.meta[filed("lhcb")] = data, map[string]string{"sha256": sha}
	read := func() int {
		return do(s, "GET", tarPath, map[string]string{"Authorization": "Bearer " + tok}).Code
	}
	admin := adminToken(t, s, "admin:alice", time.Minute, "PUT /_admin/withdraw", "PUT /_admin/lift", "GET /_admin/**")
	put := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		s.ServeAdmin(w, r)
		return w
	}
	g := gate(s).Prefix
	body := func(f map[string]string) string {
		b, _ := json.Marshal(f)
		return string(b)
	}
	ungated := ""
	for _, b := range s.bindings {
		if b.Gate == "" && b.Format == "tarballs" {
			ungated = b.Prefix
		}
	}
	if ungated == "" {
		t.Fatal("no ungated tarballs binding")
	}
	good := map[string]string{"binding": g, "sha256": sha, "key": filed("lhcb"), "why": "a licence"}
	for name, c := range map[string]struct {
		body string
		code int
	}{
		"ungated":       {body(map[string]string{"binding": ungated, "sha256": sha, "why": "x"}), 400},
		"no binding":    {body(map[string]string{"binding": "/nowhere", "sha256": sha, "why": "x"}), 404},
		"bare hex":      {body(map[string]string{"binding": g, "sha256": sha[7:], "why": "x"}), 400},
		"no why":        {body(map[string]string{"binding": g, "sha256": sha, "why": " "}), 400},
		"key elsewhere": {body(map[string]string{"binding": g, "sha256": sha, "why": "x", "key": "OTHER/x"}), 400},
		"unknown field": {body(map[string]string{"binding": g, "sha256": sha, "why": "x", "who": "x"}), 400},
		"two bodies":    {body(good) + body(good), 400},
	} {
		if w := put("/_admin/withdraw", c.body); w.Code != c.code {
			t.Errorf("%s: want %d, got %d %s", name, c.code, w.Code, w.Body)
		}
	}
	if read() != 302 || s.withdrawn.any(g) {
		t.Fatal("refused requests withdrew something")
	}
	if w := doAdmin(s, "GET", "/_admin/withdraw", map[string]string{"Authorization": "Bearer " + admin}); w.Code != 405 {
		t.Fatalf("GET withdraw: %d", w.Code)
	}
	wide := adminToken(t, s, "admin:alice", time.Minute, "PUT /_admin/**")
	if w := doAdmin(s, "PUT", "/_admin/summary", map[string]string{"Authorization": "Bearer " + wide}); w.Code != 405 {
		t.Fatalf("PUT summary: %d", w.Code)
	}
	if w := doAdmin(s, "PUT", "/_admin/nothing", map[string]string{"Authorization": "Bearer " + wide}); w.Code != 404 {
		t.Fatalf("PUT elsewhere: %d", w.Code)
	}
	if w := put("/_admin/withdraw", body(map[string]string{"binding": g, "sha256": sha, "why": strings.Repeat("x", 5000)})); w.Code != 400 {
		t.Fatalf("a body past 4 KiB: %d", w.Code)
	}
	reader := adminToken(t, s, "admin:bob", time.Minute, "GET /_admin/**")
	r := httptest.NewRequest("PUT", "/_admin/withdraw", strings.NewReader(body(good)))
	r.Header.Set("Authorization", "Bearer "+reader)
	rec := httptest.NewRecorder()
	if s.ServeAdmin(rec, r); rec.Code != 403 {
		t.Fatalf("a token allowed only GETs withdrew: %d", rec.Code)
	}

	w := put("/_admin/withdraw", body(good))
	var got struct {
		Withdrawal Withdrawal
		Added      bool
	}
	if json.Unmarshal(w.Body.Bytes(), &got); w.Code != 200 || !got.Added || got.Withdrawal.By != "admin:alice" || got.Withdrawal.Why != "a licence" {
		t.Fatalf("withdraw: %d %s", w.Code, w.Body)
	}
	if read() != 404 {
		t.Fatal("a withdrawn build read")
	}
	again := put("/_admin/withdraw", body(map[string]string{"binding": g, "sha256": sha, "why": "again"}))
	if json.Unmarshal(again.Body.Bytes(), &got); again.Code != 200 || got.Added || got.Withdrawal.Why != "a licence" {
		t.Fatalf("withdrawn twice: %d %s", again.Code, again.Body)
	}
	if w := doAdmin(s, "GET", "/_admin/withdrawn", map[string]string{"Authorization": "Bearer " + admin}); w.Code != 200 || !strings.Contains(w.Body.String(), sha) {
		t.Fatalf("the list: %d %s", w.Code, w.Body)
	}
	// kept beside the index: a service started again withdraws it too
	if again, err := openWithdrawals(file); err != nil || !again.has(g, sha) || len(again.list) != 1 {
		t.Fatalf("not kept: %v %v", err, again)
	}

	if w := put("/_admin/lift", body(map[string]string{"binding": g, "sha256": sha})); w.Code != 200 || !strings.Contains(w.Body.String(), `"denied":false`) {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	if read() != 302 {
		t.Fatal("a lifted withdrawal still withdraws")
	}
	if w := put("/_admin/lift", body(map[string]string{"binding": g, "sha256": sha})); w.Code != 404 {
		t.Fatalf("lifted twice: %d", w.Code)
	}
	if again, err := openWithdrawals(file); err != nil || again.has(g, sha) {
		t.Fatalf("the lift not kept: %v", err)
	}
	// the configuration's deny is not lifted here
	gate(s).deny = map[string]bool{sha: true}
	put("/_admin/withdraw", body(good))
	if w := put("/_admin/lift", body(map[string]string{"binding": g, "sha256": sha})); !strings.Contains(w.Body.String(), `"denied":true`) || read() != 404 {
		t.Fatalf("lifted past the configuration: %s", w.Body)
	}
	// a file that cannot be written: refused, nothing withdrawn
	gate(s).deny = nil
	s.withdrawn.path = filepath.Join(t.TempDir(), "gone", "withdrawn.json")
	if w := put("/_admin/withdraw", body(good)); w.Code != 500 || s.withdrawn.any(g) || read() != 302 {
		t.Fatalf("withdrawn without being kept: %d", w.Code)
	}
}

// A file that cannot be read stops the start: never serve builds withdrawn, unread.
func TestWithdrawalsFile(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not JSON":   "{",
		"bare hex":   `{"withdrawn": [{"binding": "/r", "sha256": "` + strings.Repeat("ab", 32) + `"}]}`,
		"no binding": `{"withdrawn": [{"sha256": "sha256:` + strings.Repeat("ab", 32) + `"}]}`,
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := openWithdrawals(p); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if w, err := openWithdrawals(filepath.Join(dir, "none")); err != nil || len(w.all()) != 0 {
		t.Fatalf("no file yet: %v", err)
	}
}

// An admin deletes one package file as seen (its ETag), not while a manifest lists it
// or one is not read yet, nor once changed in the bucket; the index forgets it.
func TestAdminDeletes(t *testing.T) {
	s, m, x, _ := gcSetup(t)
	ctx := context.Background()
	admin := adminToken(t, s, "admin:alice", time.Minute, "PUT /_admin/delete")
	tars := "/store/lhcb/x86_64-el10-gcc14-opt/t"
	del := func(code int, binding, key, etag, why string) {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"binding": binding, "key": key, "etag": etag, "why": why})
		r := httptest.NewRequest("PUT", "/_admin/delete", strings.NewReader(string(b)))
		r.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		if s.ServeAdmin(w, r); w.Code != code {
			t.Fatalf("%s: want %d, got %d %s", key, code, w.Code, w.Body)
		}
	}
	etag := func(key string) string {
		o, _ := indexed(t, s, "s3", key)
		return o.ETag
	}
	listed, other := "TT/el9/store/aa/aa/a-1-1.el9.tar.gz", "TT/el9/store/bb/bb22/b-1-1.el9.tar.gz"
	del(409, tars, listed, etag(listed), "x") // a manifest lists it
	del(409, tars, other, "old", "x")
	del(400, tars, "TT/el9/dist/x", etag("TT/el9/dist/x"), "x")
	del(400, tars, "TT/el9/store/ee/xx55/e", etag("TT/el9/store/ee/xx55/e"), "x") // its folder not its hash's
	del(400, "/store/lhcb/x86_64-el10-gcc14-opt/m", "MM/common-manifest-el9.json", etag("MM/common-manifest-el9.json"), "x")
	del(400, tars, other, etag(other), " ")
	del(400, tars, "OTHER/el9/store/bb/bb22/b", "e", "x")
	del(404, tars, "TT/el9/store/zz/zz/z-1-1.el9.tar.gz", "e", "x")
	del(404, "/nowhere", other, etag(other), "x")
	m.statFails = other
	del(502, tars, other, etag(other), "x")
	m.statFails = ""
	was := m.objs[other]
	m.objs[other] = []byte("rewritten")
	del(409, tars, other, etag(other), "x")
	m.objs[other] = was
	// a BOM not read yet may list it
	bom := "MM/release_y-1/b.el9.json"
	m.objs[bom] = []byte(`{"build_id": "release_y-1", "packages": [{"hash": "zz", "effective_architecture": "el9"}]}`)
	x.Put(ctx, s.place["s3"], index.Object{Key: bom, Size: int64(len(m.objs[bom])), ETag: m.etag(bom), Mtime: s.now()}, s.now())
	del(409, tars, other, etag(other), "x")
	s.readManifests(ctx)
	// a BOM without an architecture keeps its hash under any, as a collection has it
	never := "TT/el10/store/dd/dd44/d-1-1.el10.tar.gz"
	bom2 := "MM/release_z-1/d.json"
	m.objs[bom2] = []byte(`{"build_id": "release_z-1", "packages": [{"hash": "DD44"}]}`)
	x.Put(ctx, s.place["s3"], index.Object{Key: bom2, Size: int64(len(m.objs[bom2])), ETag: m.etag(bom2), Mtime: s.now()}, s.now())
	s.readManifests(ctx)
	del(409, tars, never, etag(never), "x")
	// an index not listed lately does not stand for the bucket
	now := s.now()
	s.now = func() time.Time { return now.Add(s.verifyEvery + 3*time.Hour) }
	admin = adminToken(t, s, "admin:alice", time.Minute, "PUT /_admin/delete")
	del(409, tars, other, etag(other), "x")
	s.now = func() time.Time { return now }
	admin = adminToken(t, s, "admin:alice", time.Minute, "PUT /_admin/delete")
	at := s.place["s3"]
	s.uploads.lease(at, "TT/el9/store/bb/bb22/", now)
	del(409, tars, other, etag(other), "x") // an upload to its folder
	s.uploads.release(at, "TT/el9/store/bb/bb22/")
	if !m.has(other) || !m.has(listed) || !m.has(never) {
		t.Fatal("deleted while refused")
	}
	s.found.set(at+"\x00TT/el9/store/bb/bb22", other, s.now())
	s.found.set(at+"\x00TT/el9/store/aa/aa", listed, s.now())
	del(200, tars, other, etag(other), "a bad build")
	if _, ok := indexed(t, s, "s3", other); ok || m.has(other) || len(s.found.hits) != 1 {
		t.Fatalf("not deleted, or still known: %v %v", m.has(other), s.found.hits)
	}
	del(404, tars, other, "e", "x")
}

// An admin plans a collection in the service: in the background, one job at a time,
// kept as -gc-out writes it (so -gc-apply takes it) with a summary; its files paged.
func TestAdminGCPlan(t *testing.T) {
	s, _, _, _ := gcSetup(t)
	var err error
	if s.gc, err = openGCJobs(filepath.Join(t.TempDir(), "gc")); err != nil {
		t.Fatal(err)
	}
	admin := adminToken(t, s, "admin:alice", time.Minute, "PUT /_admin/gc/plan", "GET /_admin/**")
	auth := map[string]string{"Authorization": "Bearer " + admin}
	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", "/_admin/gc/plan", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		s.ServeAdmin(w, r)
		return w
	}
	for _, bad := range []string{`{"max": 2}`, `{"grace": "a month"}`, `{"read": "0s", "reads": 3}`, `{"keep_builds": -1}`, `{"days": 1}`} {
		if w := put(bad); w.Code != 400 {
			t.Errorf("%s: %d %s", bad, w.Code, w.Body)
		}
	}
	if s.gc.current() != nil {
		t.Fatal("a refused plan started a job")
	}
	s.gc.job = &GCJob{Kind: "plan"} // running
	if w := put(`{}`); w.Code != 409 {
		t.Fatalf("a second job: %d", w.Code)
	}
	s.gc.job = nil
	w := put(`{"grace": "168h", "keep_builds": 0}`)
	var started struct{ ID string }
	if json.Unmarshal(w.Body.Bytes(), &started); w.Code != 202 || !gcID.MatchString(started.ID) {
		t.Fatalf("plan: %d %s", w.Code, w.Body)
	}
	for i := 0; s.gc.current().Ended == nil; i++ {
		if i > 500 {
			t.Fatal("the plan never ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var got struct {
		Job   GCJob
		Plans []GCSummary
	}
	w = doAdmin(s, "GET", "/_admin/gc", auth)
	if json.Unmarshal(w.Body.Bytes(), &got); w.Code != 200 || got.Job.Error != "" || got.Job.By != "admin:alice" ||
		len(got.Plans) != 1 || got.Plans[0].ID != started.ID || got.Plans[0].Options.Grace != "168h0m0s" {
		t.Fatalf("the job and plans: %d %s", w.Code, w.Body)
	}
	sum := got.Plans[0]
	want := 0
	for _, p := range sum.Buckets {
		for _, a := range p.Arches {
			if p.Refused == "" {
				want += a.Sweep
			}
		}
	}
	if sum.Files != want || want == 0 {
		t.Fatalf("files to go: %d, its buckets %d: %s", sum.Files, want, w.Body)
	}
	// -gc-apply takes it, with the same options
	o := DefaultGC
	o.Grace, o.KeepBuilds = 168*time.Hour, 0
	if f, err := readGCFile(filepath.Join(s.gc.dir, started.ID+".json"), o, s.now()); err != nil || len(f.Files) != want {
		t.Fatalf("not a -gc-out file: %v", err)
	}
	var page struct {
		Total int
		Files []gcFileEntry
	}
	w = doAdmin(s, "GET", "/_admin/gc/files?id="+started.ID+"&offset=1&limit=1", auth)
	if json.Unmarshal(w.Body.Bytes(), &page); w.Code != 200 || page.Total != want || len(page.Files) != min(1, want-1) {
		t.Fatalf("a page: %d %s", w.Code, w.Body)
	}
	for target, code := range map[string]int{"/_admin/gc/files?id=../../index": 400, "/_admin/gc/files?id=" + started.ID + "&limit=501": 400,
		"/_admin/gc/files?id=20000101T000000Z-000000": 404} {
		if w := doAdmin(s, "GET", target, auth); w.Code != code {
			t.Errorf("%s: want %d, got %d", target, code, w.Code)
		}
	}
	// a refused bucket's files are not counted to go
	refused := []*GCPlan{{Volume: "a", Refused: "no", Arches: []*GCArch{{Sweep: 2, SweepBytes: 10}}},
		{Volume: "b", Arches: []*GCArch{{Sweep: 1, SweepBytes: 5}}}}
	if err := s.gc.save("29990101T000000Z-000000", "x", refused, o, s.now()); err != nil {
		t.Fatal(err)
	}
	if last, err := s.gc.plans(1); err != nil || last[0].Files != 1 || last[0].Bytes != 5 {
		t.Fatalf("a refused bucket counted: %v %+v", err, last)
	}
	// a plan without its summary is not done; the newest gcKept plans are kept
	os.Remove(filepath.Join(s.gc.dir, started.ID+".summary.json"))
	if w := doAdmin(s, "GET", "/_admin/gc/files?id="+started.ID, auth); w.Code != 404 {
		t.Fatalf("a plan not done: %d", w.Code)
	}
	for i := range gcKept + 2 {
		if err := s.gc.save(fmt.Sprintf("2999%04dT000000Z-000000", 101+i), "x", refused, o, s.now()); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(s.gc.dir, "29991231T000000Z-000000.summary.json"), []byte("{"), 0o644)
	ids, _ := s.gc.ids()
	if last, err := s.gc.plans(3); err != nil || len(ids) != gcKept+1 || len(last) != 2 || last[0].ID != "29990122T000000Z-000000" {
		t.Fatalf("kept: %v; listed: %v %v", ids, err, last)
	}
	if _, err := os.Stat(filepath.Join(s.gc.dir, "29990101T000000Z-000000.json")); !os.IsNotExist(err) {
		t.Fatalf("an old plan kept: %v", err)
	}
	reader := adminToken(t, s, "admin:bob", time.Minute, "GET /_admin/**")
	r := httptest.NewRequest("PUT", "/_admin/gc/plan", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+reader)
	rec := httptest.NewRecorder()
	if s.ServeAdmin(rec, r); rec.Code != 403 {
		t.Fatalf("a token allowed only GETs planned: %d", rec.Code)
	}
}

// An admin applies a plan the service made: confirmed by its file count, in the
// background as -gc-apply does, once to its end; its lines kept in the plan's log.
func TestAdminGCApply(t *testing.T) {
	s, m, _, _ := gcSetup(t)
	ctx := context.Background()
	var err error
	if s.gc, err = openGCJobs(filepath.Join(t.TempDir(), "gc")); err != nil {
		t.Fatal(err)
	}
	o := DefaultGC
	o.Grace, o.KeepBuilds = 7*24*time.Hour, 0
	plans, err := s.PlanGC(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	id, old := "20270214T080000Z-000001", "20270201T080000Z-000002"
	if err := s.gc.save(id, "admin:bob", plans, o, s.now()); err != nil {
		t.Fatal(err)
	}
	if err := s.gc.save(old, "admin:bob", plans, o, s.now().Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sum, _ := s.gc.summary(id)
	var going []string
	for _, p := range plans {
		for _, a := range p.Arches {
			for _, f := range a.sweep {
				going = append(going, f.Key)
			}
		}
	}
	if sum.Files == 0 || sum.Files != len(going) {
		t.Fatalf("nothing to go: %+v", sum)
	}
	admin := adminToken(t, s, "admin:alice", time.Minute, "PUT /_admin/gc/apply", "GET /_admin/**")
	auth := map[string]string{"Authorization": "Bearer " + admin}
	apply := func(code int, body string) {
		t.Helper()
		r := httptest.NewRequest("PUT", "/_admin/gc/apply", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		if s.ServeAdmin(w, r); w.Code != code {
			t.Fatalf("%s: want %d, got %d %s", body, code, w.Code, w.Body)
		}
	}
	wait := func() *GCJob {
		for i := 0; ; i++ {
			if j := s.gc.current(); j != nil && j.Ended != nil {
				return j
			} else if i > 500 {
				t.Fatal("the job never ended")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	n := strconv.Itoa(sum.Files)
	apply(400, `{"id": "`+id+`"}`)
	apply(400, `{"id": "`+id+`", "files": `+strconv.Itoa(sum.Files+1)+`}`)
	apply(400, `{"id": "../index", "files": 1}`)
	apply(404, `{"id": "20000101T000000Z-000000", "files": 1}`)
	apply(409, `{"id": "`+old+`", "files": `+n+`}`) // planned more than gcPlanLife ago
	s.gc.job = &GCJob{Kind: "plan"}
	apply(409, `{"id": "`+id+`", "files": `+n+`}`)
	s.gc.job = nil
	for _, k := range going {
		if !m.has(k) {
			t.Fatalf("%s gone before the apply", k)
		}
	}
	apply(202, `{"id": "`+id+`", "files": `+n+`}`)
	if j := wait(); j.Kind != "apply" || j.Error != "" || j.By != "admin:alice" {
		t.Fatalf("the job: %+v", j)
	}
	for _, k := range going {
		if _, indexed := indexed(t, s, "s3", k); m.has(k) || indexed {
			t.Errorf("%s not deleted, or still indexed", k)
		}
	}
	if sum, _ := s.gc.summary(id); sum.Applied == nil || sum.Applied.Ended == nil || sum.Applied.Code != 0 || sum.Applied.By != "admin:alice" {
		t.Fatalf("not recorded: %+v", sum.Applied)
	}
	w := doAdmin(s, "GET", "/_admin/gc/log?id="+id, auth)
	if body := w.Body.String(); w.Code != 200 || !strings.Contains(body, "applied by admin:alice") || strings.Count(body, "deleted: ") != len(going) {
		t.Fatalf("the log: %d %s", w.Code, body)
	}
	apply(409, `{"id": "`+id+`", "files": `+n+`}`) // to its end once
	// an apply a restart stopped may be applied again: what is gone is said so
	s.gc.applied(id, &GCApplied{By: "admin:alice", Started: s.now()})
	apply(202, `{"id": "`+id+`", "files": `+n+`}`)
	wait()
	if body := doAdmin(s, "GET", "/_admin/gc/log?id="+id, auth).Body.String(); strings.Count(body, "applied by") != 2 ||
		strings.Count(body, "deleted: ") != len(going) {
		t.Fatalf("not applied again: %s", body)
	}
	// a long log: its last MiB, from a whole line
	long := strings.Repeat("x", 99) + "\n"
	os.WriteFile(filepath.Join(s.gc.dir, old+".log"), []byte(strings.Repeat(long, 11000)+"the end\n"), 0o644)
	if body := doAdmin(s, "GET", "/_admin/gc/log?id="+old, auth).Body.String(); len(body) > 1<<20 || !strings.HasPrefix(body, long) ||
		!strings.HasSuffix(body, "the end\n") {
		t.Fatalf("the log's tail: %d bytes, %q", len(body), body[:20])
	}
	os.Remove(filepath.Join(s.gc.dir, old+".log"))
	for target, code := range map[string]int{"/_admin/gc/log?id=..%2Findex": 400, "/_admin/gc/log?id=" + old: 404} {
		if w := doAdmin(s, "GET", target, auth); w.Code != code {
			t.Errorf("%s: want %d, got %d", target, code, w.Code)
		}
	}
}
