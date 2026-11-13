// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/format"
)

type vectors struct {
	Issuer, Audience string
	Now              int64
	Keys             map[string]KeyConfig
	Cases            []struct{ Name, Token string }
}

// tokenNamed returns the token of a named vector case.
func tokenNamed(t *testing.T, name string) string {
	b, err := os.ReadFile("../../testdata/tokens/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		if c.Name == name {
			return c.Token
		}
	}
	t.Fatalf("no case %s", name)
	return ""
}

// Test formats: one naming a key outside the path rules, one naming nothing.
type escapeFormat struct{}

func (escapeFormat) Name() string { return "test-escape" }
func (escapeFormat) Route([]string) (format.Item, error) {
	return format.Item{Key: "../x"}, nil
}

type noneFormat struct{}

func (noneFormat) Name() string { return "test-none" }
func (noneFormat) Route([]string) (format.Item, error) {
	return format.Item{}, errors.New("nothing")
}

func init() {
	format.Register(escapeFormat{})
	format.Register(noneFormat{})
}

// setup serves the test vectors' issuer and keys; good is the vectors' first token
// (GET /store/lhcb/x86_64-el10*/**, GET /sources/archives/*, expires at now+3600).
func setup(t *testing.T) (s *Server, good string, now time.Time) {
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
	c := &Config{Issuer: v.Issuer, Audience: v.Audience, Keys: v.Keys,
		Volumes: map[string]VolumeConf{
			"s3":   {Endpoint: "https://s3.example.org", Bucket: "bits", Region: "us-east-1", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"},
			"pub":  {Endpoint: "https://s3.example.org", Bucket: "open", Region: "us-east-1"},
			"pub2": {Endpoint: "https://s3.example.org", Bucket: "open2", Region: "us-east-1"},
		},
		Bindings: []Binding{
			{Prefix: "/store/lhcb", Volume: "s3", KeyPrefix: "TARS"},
			{Prefix: "/store/lhcb/x86_64-el10", Volume: "s3", KeyPrefix: "EL10"},
			{Prefix: "/sources/archives", Volume: "s3", KeyPrefix: "SOURCES/cache"},
			{Prefix: "/public", Volume: "pub", Public: true},
			{Prefix: "/store/lhcb/x86_64-el10-esc", Volume: "s3", KeyPrefix: "ESC", Format: "test-escape"},
			{Prefix: "/test/none", Volume: "pub2", Public: true, Format: "test-none"},
			{Prefix: "/test/none-private", Volume: "s3", KeyPrefix: "NONE", Format: "test-none"},
			{Prefix: "/store/lhcb/x86_64-el10-src", Volume: "s3", KeyPrefix: "SRC", Format: "sources", MaxSize: 1000},
			{Prefix: "/store/lhcb/x86_64-el10-pubsrc", Volume: "s3", KeyPrefix: "PUBSRC", Format: "sources", Public: true},
			{Prefix: "/pubsrc", Volume: "s3", KeyPrefix: "PUBSRC2", Format: "sources", Public: true}, // beyond the token
			{Prefix: "/store/lhcb/x86_64-el10-gcc14-opt/t", Volume: "s3", KeyPrefix: "TT", Format: "tarballs"},
			{Prefix: "/store/lhcb/x86_64-el10-gcc14-opt/pt", Volume: "s3", KeyPrefix: "PUBT", Format: "tarballs", Public: true}, // within the PUT
		}}
	if s, err = New(c); err != nil {
		t.Fatal(err)
	}
	now = time.Unix(v.Now, 0)
	s.now = func() time.Time { return now }
	return s, v.Cases[0].Token, now
}

func do(s *Server, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestRequests(t *testing.T) {
	s, good, _ := setup(t)
	auth := map[string]string{"Authorization": "Bearer " + good}
	for _, c := range []struct {
		name, method, target string
		hdr                  map[string]string
		code                 int
		key                  string // the object key the redirect must name
	}{
		{"health", "GET", "/health", nil, 200, ""},
		{"public-no-token", "GET", "/public/a/b", nil, 302, "/open/a/b"},
		{"public-plus-escaped", "GET", "/public/a+b", nil, 302, "/open/a+b"},
		{"private-no-token", "GET", "/sources/archives/x", nil, 401, ""},
		{"allowed", "GET", "/sources/archives/x?ignored=1", auth, 302, "/bits/SOURCES/cache/x"},
		{"head", "HEAD", "/sources/archives/x", auth, 302, "/bits/SOURCES/cache/x"},
		{"store", "GET", "/store/lhcb/x86_64-el10-gcc14-opt/ab/h", auth, 302, "/bits/TARS/x86_64-el10-gcc14-opt/ab/h"},
		{"longest-prefix", "GET", "/store/lhcb/x86_64-el10/ab", auth, 302, "/bits/EL10/ab"},
		{"no-capability", "GET", "/sources/archives/a/b", auth, 403, ""},
		{"no-binding", "GET", "/store/atlas/x", auth, 404, ""},
		{"no-binding-no-token", "GET", "/store/atlas/x", nil, 401, ""},
		{"prefix-alone", "GET", "/sources/archives", auth, 404, ""},
		{"encoded-slash", "GET", "/sources/archives/a%2Fb", auth, 400, ""},
		{"dotdot", "GET", "/sources/archives/../x", auth, 400, ""},
		{"bad-token", "GET", "/sources/archives/x", map[string]string{"Authorization": "Bearer " + good[:len(good)-2] + "AA"}, 401, ""},
		{"cookie", "GET", "/sources/archives/x", map[string]string{"Cookie": cookieName + "=" + good}, 302, "/bits/SOURCES/cache/x"},
		{"header-wins-over-cookie", "GET", "/sources/archives/x", map[string]string{"Authorization": "Basic eDp5", "Cookie": cookieName + "=" + good}, 401, ""},
		{"put-not-yet", "PUT", "/sources/archives/x", auth, 405, ""},
		{"format-key-escapes", "GET", "/store/lhcb/x86_64-el10-esc/x", auth, 404, ""},
		{"format-key-escapes-no-token", "GET", "/store/lhcb/x86_64-el10-esc/x", nil, 401, ""},
		{"format-no-capability-first", "GET", "/test/none-private/x", auth, 403, ""},
		{"format-finds-nothing-public", "GET", "/test/none/x", nil, 404, ""},
	} {
		w := do(s, c.method, c.target, c.hdr)
		if w.Code != c.code {
			t.Errorf("%s: want %d, got %d", c.name, c.code, w.Code)
			continue
		}
		if c.code == 401 && w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: no WWW-Authenticate", c.name)
		}
		if c.key != "" {
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil || u.Host != "s3.example.org" || u.Path != c.key {
				t.Errorf("%s: Location %q, want path %s", c.name, w.Header().Get("Location"), c.key)
			}
			if !strings.HasPrefix(c.target, "/public/") && u.Query().Get("X-Amz-Signature") == "" {
				t.Errorf("%s: not presigned", c.name)
			}
		}
	}
}

func TestHeadAndGetDiffer(t *testing.T) {
	s, good, _ := setup(t)
	auth := map[string]string{"Authorization": "Bearer " + good}
	g := do(s, "GET", "/sources/archives/x", auth).Header().Get("Location")
	h := do(s, "HEAD", "/sources/archives/x", auth).Header().Get("Location")
	if g == "" || g == h {
		t.Fatal("HEAD must get its own signature: S3 signs the method")
	}
}

func TestURLNeverOutlivesToken(t *testing.T) {
	s, good, now := setup(t)
	auth := map[string]string{"Authorization": "Bearer " + good}
	end := now.Add(3600 * time.Second) // the token's exp
	s.now = func() time.Time { return end.Add(-10 * time.Second) }
	u, _ := url.Parse(do(s, "GET", "/sources/archives/x", auth).Header().Get("Location"))
	if got := u.Query().Get("X-Amz-Expires"); got != "10" {
		t.Fatalf("expires %s, want 10", got)
	}
	s.now = func() time.Time { return end.Add(61 * time.Second) } // cached, but expired
	if w := do(s, "GET", "/sources/archives/x", auth); w.Code != 401 {
		t.Fatalf("expired token from the cache: %d", w.Code)
	}
}

func TestConfigRefused(t *testing.T) {
	base := func() *Config {
		return &Config{Issuer: "i", Audience: "a",
			Keys:     map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
			Volumes:  map[string]VolumeConf{"v": {Endpoint: "https://s3.example.org", Bucket: "bucket", Region: "r"}},
			Bindings: []Binding{{Prefix: "/a", Volume: "v", Public: true}}}
	}
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	if _, err := New(base()); err != nil {
		t.Fatalf("base config refused: %v", err)
	}
	for name, change := range map[string]func(*Config){
		"no-region": func(c *Config) { c.Volumes["v"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "b"} },
		"endpoint-path": func(c *Config) {
			c.Volumes["v"] = VolumeConf{Endpoint: "https://s3.example.org/x", Bucket: "bucket", Region: "r"}
		},
		"missing-key": func(c *Config) {
			c.Volumes["v"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bucket", Region: "r", AccessKeyEnv: "NOPE_AK", SecretKeyEnv: "NOPE_SK"}
		},
		"bad-prefix":   func(c *Config) { c.Bindings[0].Prefix = "/a/../b" },
		"no-volume":    func(c *Config) { c.Bindings[0].Volume = "w" },
		"duplicate":    func(c *Config) { c.Bindings = append(c.Bindings, c.Bindings[0]) },
		"slash-key":    func(c *Config) { c.Bindings[0].KeyPrefix = "TARS/" },
		"bad-signer":   func(c *Config) { c.Keys["k"] = KeyConfig{X: strings.Repeat("A", 43), Signer: "bulid"} },
		"url-lifetime": func(c *Config) { c.URLLifetime = "2h" },
		"private-anon": func(c *Config) { c.Bindings[0].Public = false },
		"public-keyed": func(c *Config) {
			c.Volumes["k"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bucket", Region: "r", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
			c.Bindings[0].Volume = "k"
		},
		"overlap": func(c *Config) {
			c.Bindings[0].KeyPrefix = "A"
			c.Bindings = append(c.Bindings, Binding{Prefix: "/b", Volume: "v", KeyPrefix: "A/B", Public: true})
		},
		"overlap-other-volume-name": func(c *Config) {
			c.Volumes["v2"] = c.Volumes["v"]
			c.Bindings = append(c.Bindings, Binding{Prefix: "/b", Volume: "v2", KeyPrefix: "X", Public: true})
		},
		"key-prefix-dotdot":    func(c *Config) { c.Bindings[0].KeyPrefix = "../X" },
		"key-prefix-empty-seg": func(c *Config) { c.Bindings[0].KeyPrefix = "a//b" },
		"endpoint-userinfo": func(c *Config) {
			c.Volumes["v"] = VolumeConf{Endpoint: "https://u:p@s3.example.org", Bucket: "bucket", Region: "r"}
		},
		"endpoint-query": func(c *Config) {
			c.Volumes["v"] = VolumeConf{Endpoint: "https://s3.example.org?x=1", Bucket: "bucket", Region: "r"}
		},
		"http": func(c *Config) {
			c.Volumes["v"] = VolumeConf{Endpoint: "http://s3.example.org", Bucket: "bucket", Region: "r"}
		},
		"bad-bucket-2": func(c *Config) {
			c.Volumes["v"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "b", Region: "r"}
		},
		"bad-bucket": func(c *Config) {
			c.Volumes["v"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "B_ad", Region: "r"}
		},
		"no-bindings":         func(c *Config) { c.Bindings = nil },
		"unknown-format":      func(c *Config) { c.Bindings[0].Format = "nope" },
		"max-lifetime-zero":   func(c *Config) { c.MaxLifetime = "0s" },
		"mirror-anonymous":    func(c *Config) { c.Bindings[0].Format = "sources" },
		"tarballs-anonymous":  func(c *Config) { c.Bindings[0].Format = "tarballs" },
		"max-size-not-mirror": func(c *Config) { c.Bindings[0].MaxSize = 1 },
		"access-log":          func(c *Config) { c.AccessLog = "some" },
		"site-range":          func(c *Config) { c.Fetch.SiteRanges = []string{"10.0.0.0"} },
		"max-size-negative": func(c *Config) {
			c.Volumes["k"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "b2b", Region: "r", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
			c.Bindings = append(c.Bindings, Binding{Prefix: "/s", Volume: "k", KeyPrefix: "S", Format: "sources", MaxSize: -1})
		},
		"max-size-too-big": func(c *Config) {
			c.Volumes["k"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "b2b", Region: "r", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
			c.Bindings = append(c.Bindings, Binding{Prefix: "/s", Volume: "k", KeyPrefix: "S", Format: "sources", MaxSize: 1 << 50})
		},
		"public-over-staging": func(c *Config) {
			c.Volumes["k"] = VolumeConf{Endpoint: "https://s3.example.org", Bucket: "bucket", Region: "r", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}
			c.Bindings[0].KeyPrefix = "STAGING"
		},
	} {
		c := base()
		change(c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBearer(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer a")
	r.Header.Add("Authorization", "Bearer b")
	if bearer(r) != "" {
		t.Fatal("two Authorization headers must give no token")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "bearer t")
	if bearer(r) != "t" {
		t.Fatal("the scheme is case-insensitive")
	}
}

func TestPlainURLEscapesPlus(t *testing.T) {
	s, _, _ := setup(t)
	if loc := do(s, "GET", "/public/a+b", nil).Header().Get("Location"); loc != "https://s3.example.org/open/a%2Bb" {
		t.Fatalf("Location %q", loc)
	}
}

func TestHTTPAllowedExplicitly(t *testing.T) {
	c := &Config{Issuer: "i", Audience: "a",
		Keys:     map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
		Volumes:  map[string]VolumeConf{"v": {Endpoint: "http://minio:9000", Bucket: "bucket", Region: "r", AllowHTTP: true}},
		Bindings: []Binding{{Prefix: "/a", Volume: "v", Public: true}}}
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
}
