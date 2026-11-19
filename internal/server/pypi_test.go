// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// userToken is a token of the vectors' user key test-1 for sft, allowed caps.
func userToken(t *testing.T, s *Server, caps ...string) string {
	seed := sha256.Sum256([]byte("bits-store test key 1"))
	k := ed25519.NewKeyFromSeed(seed[:])
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	var cs []map[string]string
	for _, c := range caps {
		m, p, _ := strings.Cut(c, " ")
		cs = append(cs, map[string]string{"m": m, "p": p})
	}
	iat := s.now().Unix()
	si := enc(map[string]string{"alg": "EdDSA", "typ": "bits-store+jwt", "kid": "test-1"}) + "." +
		enc(map[string]any{"iss": s.verifier.Issuer, "aud": s.verifier.Audience, "sub": "alice", "grp": "sft",
			"iat": iat, "exp": iat + 3600, "jti": fmt.Sprint(caps), "cap": cs})
	return si + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, []byte(si)))
}

// pip reads a project's page here, made from the index's with links back here, and
// a file from the index the first time, while the store fetches it; then from the store.
func TestPyPI(t *testing.T) {
	s, good, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	anyAddr(t)
	data, other := []byte("a wheel"), []byte("not the wheel the index lists")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	whl, bad := "demo_pkg-1.0-py3-none-any.whl", "demo_pkg-1.1-py3-none-any.whl"
	var pageHits atomic.Int32
	var down atomic.Bool
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/demo-pkg/":
			if down.Load() || r.Header.Get("Accept") != pypiJSON {
				w.WriteHeader(503)
				return
			}
			pageHits.Add(1)
			fmt.Fprintf(w, `{"files": [
				{"filename": %q, "url": "../../f/%s#sha256=%s", "hashes": {"sha256": %q}, "requires-python": ">=3.8", "yanked": "broken"},
				{"filename": %q, "url": "/f/%s", "hashes": {"sha256": %q}},
				{"filename": "nohash-1.0.tar.gz", "url": "/f/nohash", "hashes": {}},
				{"filename": "ftp-1.0.tar.gz", "url": "ftp://example.org/ftp-1.0.tar.gz", "hashes": {"sha256": %q}},
				{"filename": "bad name-1.0.tar.gz", "url": "/f/bad", "hashes": {"sha256": %q}}]}`,
				whl, whl, sha, sha, bad, bad, strings.Repeat("ab", 32), sha, sha)
		case "/f/" + whl:
			w.Write(data)
		case "/f/" + bad:
			w.Write(other)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(idx.Close)
	vol := VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bits", Region: "us-east-1", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
	bs, err := (&Config{Volumes: map[string]VolumeConf{"s3": vol},
		Bindings: []Binding{{Prefix: "/pypi", Volume: "s3", KeyPrefix: "PYPI", Format: "pypi"}}}).bindings()
	if err != nil {
		t.Fatal(err)
	}
	bs[0].Index = idx.URL + "/simple"
	s.bindings = append(s.bindings, bs[0])
	tok := userToken(t, s, "GET /pypi/**")
	pip := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("bits:"+tok)), "Accept": pypiJSON}

	w := do(s, "GET", "/pypi/simple/demo-pkg/", pip)
	var page struct {
		Files []struct {
			Filename, URL  string
			Hashes         map[string]string
			RequiresPython string          `json:"requires-python"`
			Yanked         json.RawMessage `json:"yanked"`
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &page); w.Code != 200 || w.Header().Get("Content-Type") != pypiJSON || len(page.Files) != 2 {
		t.Fatalf("the page: %d %s", w.Code, w.Body)
	}
	f := page.Files[0]
	link := "/pypi/files/demo-pkg/" + sha + "/" + whl
	if f.Filename != whl || f.URL != link || f.Hashes["sha256"] != sha || f.RequiresPython != ">=3.8" || string(f.Yanked) != `"broken"` {
		t.Fatalf("a file: %+v", f)
	}
	do(s, "GET", "/pypi/simple/demo-pkg/", pip)
	if pageHits.Load() != 1 {
		t.Fatalf("the index asked %d times within %s", pageHits.Load(), pageTTL)
	}
	for name, c := range map[string]struct {
		target string
		hdr    map[string]string
		code   int
	}{
		"html only":            {"/pypi/simple/demo-pkg/", map[string]string{"Authorization": pip["Authorization"], "Accept": "text/html"}, 406},
		"no token":             {"/pypi/simple/demo-pkg/", map[string]string{"Accept": pypiJSON}, 401},
		"another's binding":    {"/pypi/simple/demo-pkg/", map[string]string{"Authorization": "Bearer " + good, "Accept": pypiJSON}, 403},
		"not normalised":       {"/pypi/simple/Demo_Pkg/", pip, 404},
		"no such project":      {"/pypi/simple/none/", pip, 404},
		"not on its page":      {"/pypi/files/demo-pkg/" + strings.Repeat("cd", 32) + "/" + whl, pip, 404},
		"slash elsewhere":      {"/sources/archives/x/", map[string]string{"Authorization": "Bearer " + good}, 400},
		"uploads not accepted": {"/pypi/files/demo-pkg/" + sha + "/" + whl + "?uploads", map[string]string{"Authorization": "Bearer " + userToken(t, s, "PUT /pypi/**")}, 405},
	} {
		method := "GET"
		if strings.HasSuffix(c.target, "?uploads") {
			method = "POST"
		}
		if w := do(s, method, c.target, c.hdr); w.Code != c.code {
			t.Errorf("%s: want %d, got %d %s", name, c.code, w.Code, w.Body)
		}
	}

	// the first read: from the index, while the store fetches it
	key := "PYPI/files/demo-pkg/" + sha + "/" + whl
	if w := do(s, "GET", link, pip); w.Code != 302 || w.Header().Get("Location") != idx.URL+"/f/"+whl {
		t.Fatalf("first read: %d %v", w.Code, w.Header())
	}
	settled(t, s)
	if !m.has(key) || m.meta[key]["sha256"] != "sha256:"+sha {
		t.Fatalf("not kept: %v", m.meta[key])
	}
	if w := do(s, "GET", link, pip); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "mem/"+key) {
		t.Fatalf("then from the store: %d %v", w.Code, w.Header())
	}
	// bytes other than the index lists are not kept
	badLink := "/pypi/files/demo-pkg/" + strings.Repeat("ab", 32) + "/" + bad
	do(s, "GET", badLink, pip)
	settled(t, s)
	if m.has("PYPI/files/demo-pkg/"+strings.Repeat("ab", 32)+"/"+bad) || len(m.objs) != 1 {
		t.Fatalf("other bytes kept: %v", keys(m))
	}
	// the index down: its last page still served, and a kept file without it
	down.Store(true)
	s.now = func() time.Time { return now.Add(pageTTL + time.Minute) }
	tok = userToken(t, s, "GET /pypi/**")
	pip["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte("bits:"+tok))
	if w := do(s, "GET", "/pypi/simple/demo-pkg/", pip); w.Code != 200 || !strings.Contains(w.Body.String(), whl) {
		t.Fatalf("a stale page: %d %s", w.Code, w.Body)
	}
	if w := do(s, "GET", link, pip); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "mem/"+key) {
		t.Fatalf("a kept file, the index down: %d", w.Code)
	}
	s.pages = &pageCache{}
	if w := do(s, "GET", "/pypi/simple/demo-pkg/", pip); w.Code != 502 {
		t.Fatalf("no page at all: %d", w.Code)
	}
}

func keys(m *memStore) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objs {
		out = append(out, k)
	}
	return out
}

// A pypi binding fetches, public or not; index is its alone, an https:// URL.
func TestPyPIConfig(t *testing.T) {
	vol := VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bits", Region: "us-east-1", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
	for name, c := range map[string]struct {
		b  Binding
		ok bool
	}{
		"plain":           {Binding{Prefix: "/pypi", Volume: "s3", KeyPrefix: "PYPI", Format: "pypi"}, true},
		"index":           {Binding{Prefix: "/pypi", Volume: "s3", KeyPrefix: "PYPI", Format: "pypi", Index: "https://mirror.example.org/simple"}, true},
		"http index":      {Binding{Prefix: "/pypi", Volume: "s3", KeyPrefix: "PYPI", Format: "pypi", Index: "http://mirror.example.org/simple"}, false},
		"public":          {Binding{Prefix: "/pypi", Volume: "s3", KeyPrefix: "PYPI", Format: "pypi", Public: true}, true},
		"index elsewhere": {Binding{Prefix: "/x", Volume: "s3", KeyPrefix: "X", Index: "https://mirror.example.org/simple"}, false},
	} {
		bs, err := (&Config{Volumes: map[string]VolumeConf{"s3": vol}, Bindings: []Binding{c.b}}).bindings()
		if (err == nil) != c.ok || c.ok && bs[0].MaxSize != defaultMaxSize {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// pip reads a project's files in a burst: a file with no room to be fetched waits
// for some, and is kept as the others are.
func TestPyPIWaitsForRoom(t *testing.T) {
	s, _, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	anyAddr(t)
	defer func(w, p time.Duration) { roomWait, roomPoll = w, p }(roomWait, roomPoll)
	roomWait, roomPoll = 5*time.Second, 10*time.Millisecond
	n := maxFetchPerSubject + 1
	gate := make(chan struct{})
	var files []string
	for i := range n {
		data := fmt.Sprintf("wheel %d", i)
		sum := sha256.Sum256([]byte(data))
		files = append(files, fmt.Sprintf(`{"filename": "p-%d-py3-none-any.whl", "url": "/f/%d", "hashes": {"sha256": "%x"}}`, i, i, sum))
	}
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/p/" {
			fmt.Fprintf(w, `{"files": [%s]}`, strings.Join(files, ","))
			return
		}
		<-gate // the first fetches hold their slots until the test lets them go
		fmt.Fprintf(w, "wheel %s", strings.TrimPrefix(r.URL.Path, "/f/"))
	}))
	t.Cleanup(idx.Close)
	vol := VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bits", Region: "us-east-1", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
	bs, err := (&Config{Volumes: map[string]VolumeConf{"s3": vol},
		Bindings: []Binding{{Prefix: "/pypi", Volume: "s3", KeyPrefix: "PYPI", Format: "pypi"}}}).bindings()
	if err != nil {
		t.Fatal(err)
	}
	bs[0].Index = idx.URL + "/simple"
	s.bindings = append(s.bindings, bs[0])
	pip := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("bits:"+userToken(t, s, "GET /pypi/**"))), "Accept": pypiJSON}
	var page struct{ Files []struct{ URL string } }
	if w := do(s, "GET", "/pypi/simple/p/", pip); json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Files) != n {
		t.Fatalf("the page: %d %s", w.Code, w.Body)
	}
	for _, f := range page.Files {
		if w := do(s, "GET", f.URL, pip); w.Code != 302 {
			t.Fatalf("%s: %d", f.URL, w.Code)
		}
	}
	close(gate)
	kept := func() (k int) {
		for _, f := range page.Files {
			if m.has("PYPI" + strings.TrimPrefix(f.URL, "/pypi")) {
				k++
			}
		}
		return k
	}
	for i := 0; kept() < n; i++ {
		if i > 300 {
			t.Fatalf("kept %d of %d: %v", kept(), n, keys(m))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A public pypi binding: pip reads it without a token, and a first read still has
// the file fetched into the store, then read from it by its plain URL.
func TestPyPIPublic(t *testing.T) {
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	kcs := map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}}
	vols := map[string]VolumeConf{
		"s3":  {Endpoint: "https://s3.example.org", Bucket: "bits", Region: "r", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"},
		"pub": {Endpoint: "https://s3.example.org", Bucket: "open", Region: "r"}}
	pub := Binding{Prefix: "/pypi", Volume: "pub", KeyPrefix: "PYPI", Format: "pypi", Public: true}
	if _, err := New(&Config{Issuer: "i", Audience: "a", Keys: kcs, Volumes: vols, Bindings: []Binding{pub}}); err == nil {
		t.Fatal("a pypi binding on a volume without keys: it could not fetch")
	}
	pub.Volume = "s3"
	s, err := New(&Config{Issuer: "i", Audience: "a", Keys: kcs, Volumes: vols, Bindings: []Binding{pub}})
	if err != nil {
		t.Fatal(err)
	}
	m := newMem()
	s.stores["s3"] = m
	anyAddr(t)
	data := []byte("a wheel")
	sum := sha256.Sum256(data)
	sha, whl := hex.EncodeToString(sum[:]), "demo-1.0-py3-none-any.whl"
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/demo/":
			fmt.Fprintf(w, `{"files": [{"filename": %q, "url": "/f/%s", "hashes": {"sha256": %q}}]}`, whl, whl, sha)
		case "/f/" + whl:
			w.Write(data)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(idx.Close)
	s.bindings[0].Index = idx.URL + "/simple"
	pip := map[string]string{"Accept": pypiJSON} // no token
	if w := do(s, "GET", "/pypi/simple/demo/", pip); w.Code != 200 || !strings.Contains(w.Body.String(), whl) {
		t.Fatalf("the page: %d %s", w.Code, w.Body)
	}
	link, key := "/pypi/files/demo/"+sha+"/"+whl, "PYPI/files/demo/"+sha+"/"+whl
	if w := do(s, "GET", link, pip); w.Code != 302 || w.Header().Get("Location") != idx.URL+"/f/"+whl {
		t.Fatalf("first read: %d %v", w.Code, w.Header())
	}
	settled(t, s)
	if !m.has(key) {
		t.Fatalf("not kept: %v", keys(m))
	}
	if w := do(s, "GET", link, pip); w.Code != 302 || w.Header().Get("Location") != "https://s3.example.org/bits/"+key {
		t.Fatalf("then from the store, by its plain URL: %d %v", w.Code, w.Header())
	}
}
