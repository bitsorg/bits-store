// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// git runs git for a test, isolated from the host's configuration and proxies.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := gitIn(dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(out)
}

func gitIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-c", "protocol.version=2", "-c", "init.defaultBranch=main",
		"-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// gitUpstream is a repository served by git http-backend, counting the fetches
// made of it (protocol v2's command=fetch).
type gitUpstream struct {
	srv     *httptest.Server
	work    string
	fetches atomic.Int32
}

func newGitUpstream(t *testing.T) *gitUpstream {
	root := t.TempDir()
	u := &gitUpstream{work: filepath.Join(root, "work")}
	git(t, root, "init", "-q", "--bare", "up.git")
	git(t, filepath.Join(root, "up.git"), "config", "uploadpack.allowFilter", "true")
	git(t, filepath.Join(root, "up.git"), "config", "uploadpack.allowAnySHA1InWant", "true")
	git(t, root, "init", "-q", "work")
	git(t, u.work, "remote", "add", "origin", filepath.Join(root, "up.git"))
	exe, _ := exec.Command("git", "--exec-path").Output()
	h := &cgi.Handler{Path: filepath.Join(strings.TrimSpace(string(exe)), "git-http-backend"),
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1"}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			if bytes.Contains(b, []byte("command=fetch")) {
				u.fetches.Add(1)
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// commit adds a file and tags the commit (moved with force, as upstreams do).
func (u *gitUpstream) commit(t *testing.T, file, text, tag string) string {
	os.MkdirAll(filepath.Join(u.work, filepath.Dir(file)), 0o755)
	os.WriteFile(filepath.Join(u.work, file), []byte(text), 0o644)
	git(t, u.work, "add", "-A")
	git(t, u.work, "commit", "-q", "-m", text)
	git(t, u.work, "tag", "-f", tag)
	git(t, u.work, "push", "-q", "-f", "origin", "main", "refs/tags/"+tag)
	return git(t, u.work, "rev-parse", tag)
}

// The git binding: clones and fetches through the store come from its partial
// mirror, filled from upstream by the refs asked for; a tag held never moves.
func TestGit(t *testing.T) {
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	anyAddr(t)
	defer func(s string) { gitScheme = s }(gitScheme)
	gitScheme = "http"
	up := newGitUpstream(t)
	v1 := up.commit(t, "dir/a.txt", "one", "v1")
	s, err := New(&Config{Issuer: "i", Audience: "a", Keys: map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
		Volumes: map[string]VolumeConf{"s3": {Endpoint: "https://s3.example.org", Bucket: "bits", Region: "r",
			AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}},
		Bindings: []Binding{{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git", Public: true}}})
	if err != nil {
		t.Fatal(err)
	}
	s.git.root = t.TempDir()
	var at atomic.Int64 // the store's clock, moved by the test
	at.Store(time.Now().UnixNano())
	s.now = func() time.Time { return time.Unix(0, at.Load()) }
	later := func() { at.Add(int64(refsTTL + time.Minute)) }
	store := httptest.NewServer(s)
	t.Cleanup(store.Close)
	url := store.URL + "/git/" + strings.TrimPrefix(up.srv.URL, "http://") + "/up"

	// a clone as bits makes it, then the tag it builds: files from the store
	c := t.TempDir()
	git(t, c, "clone", "-q", "--bare", "--filter=tree:0", url, "c.git")
	cg := filepath.Join(c, "c.git")
	git(t, cg, "fetch", "-q", "--filter=tree:0", "origin", "refs/tags/v1:refs/tags/v1")
	if got := git(t, cg, "show", "v1:dir/a.txt"); got != "one" {
		t.Fatalf("v1:dir/a.txt through the store: %q", got)
	}
	mirror := filepath.Join(s.git.root, "GIT", strings.TrimPrefix(up.srv.URL, "http://"), "up.git")
	if got := git(t, mirror, "rev-parse", "refs/bits/"+v1); got != v1 {
		t.Fatalf("the commit wanted is not kept: %q", got)
	}
	// a new tag upstream: fetched by name (git names it), at once
	v2 := up.commit(t, "b.txt", "two", "v2")
	git(t, cg, "fetch", "-q", "--filter=tree:0", "origin", "refs/tags/v2:refs/tags/v2")
	if got := git(t, cg, "rev-parse", "v2"); got != v2 {
		t.Fatalf("a new tag: %q, want %s", got, v2)
	}
	// a tag moved upstream: the store keeps it as it was
	moved := up.commit(t, "c.txt", "three", "v1")
	later()
	if got := git(t, c, "ls-remote", url, "refs/tags/v1"); !strings.HasPrefix(got, v1) || moved == v1 {
		t.Fatalf("a moved tag: %q, want %s (not %s)", got, v1, moved)
	}
	// branches follow upstream
	if got := git(t, c, "ls-remote", url, "refs/heads/main"); !strings.HasPrefix(got, moved) {
		t.Fatalf("main: %q, want %s", got, moved)
	}

	// two clients at once, different new tags and the same one: all served, one
	// upstream fill for the tag both ask
	up.commit(t, "d.txt", "four", "v4")
	up.commit(t, "e.txt", "five", "v5")
	later()
	before := up.fetches.Load()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i, tag := range []string{"v4", "v5", "v5", "v5"} {
		wg.Add(1)
		go func(i int, tag string) {
			defer wg.Done()
			d := t.TempDir()
			if out, err := gitIn(d, "clone", "-q", "--bare", "--filter=tree:0", url, "x.git"); err != nil {
				errs <- err
				t.Log(out)
				return
			}
			out, err := gitIn(filepath.Join(d, "x.git"), "fetch", "-q", "--filter=tree:0", "origin", "refs/tags/"+tag+":refs/tags/"+tag)
			if err == nil {
				out, err = gitIn(filepath.Join(d, "x.git"), "show", tag+":"+map[string]string{"v4": "d.txt", "v5": "e.txt"}[tag])
			}
			if err != nil {
				t.Log(out)
				errs <- err
			}
		}(i, tag)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// a refresh, then per new commit its trees and its files: not once per client
	if n := up.fetches.Load() - before; n > 5 {
		t.Fatalf("%d fetches upstream for 4 clients of 2 new tags", n)
	}

	// upstream down: what is held is still served
	up.srv.Close()
	later()
	if got := git(t, c, "ls-remote", url, "refs/tags/v2"); !strings.HasPrefix(got, v2) {
		t.Fatalf("upstream down: %q", got)
	}
}

// Requests git's mirror does not take: a push, an old client (sent upstream).
func TestGitRequests(t *testing.T) {
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	s, err := New(&Config{Issuer: "i", Audience: "a", Keys: map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
		Volumes: map[string]VolumeConf{"s3": {Endpoint: "https://s3.example.org", Bucket: "bits", Region: "r",
			AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}},
		Bindings: []Binding{{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git", Public: true}}})
	if err != nil {
		t.Fatal(err)
	}
	s.git.root = t.TempDir()
	for name, c := range map[string]struct {
		method, target, proto string
		code                  int
		loc                   string
	}{
		"push":                {"GET", "/git/github.com/a/b/info/refs?service=git-receive-pack", "version=2", 403, ""},
		"receive-pack":        {"POST", "/git/github.com/a/b/git-receive-pack", "version=2", 401, ""},
		"protocol v0":         {"GET", "/git/github.com/a/b/info/refs?service=git-upload-pack", "", 302, "https://github.com/a/b/info/refs?service=git-upload-pack"},
		"not pkt-lines":       {"POST", "/git/github.com/a/b/git-upload-pack", "version=2", 400, ""},
		"a full clone":        {"POST", "/git/github.com/a/b/git-upload-pack", "version=2", 400, ""},
		"an option as a want": {"POST", "/git/github.com/a/b/git-upload-pack", "version=2", 400, ""},
	} {
		body := "hello"
		if name == "a full clone" { // no filter: refused before any fetch upstream
			body = pkt("command=fetch\n") + "0001" + pkt("want "+strings.Repeat("ab", 20)+"\n") + "0000"
		}
		if name == "an option as a want" {
			body = pkt("command=fetch\n") + "0001" + pkt("filter tree:0\n") + pkt("want --output=/tmp/x\n") + "0000"
		}
		r := httptest.NewRequest(c.method, c.target, strings.NewReader(body))
		if c.proto != "" {
			r.Header.Set("Git-Protocol", c.proto)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != c.code || w.Header().Get("Location") != c.loc {
			t.Errorf("%s: %d %q, want %d %q", name, w.Code, w.Header().Get("Location"), c.code, c.loc)
		}
	}
}

// A git binding needs a volume with keys (the repositories' bundles go there) and
// fetches nothing by size.
func TestGitConfig(t *testing.T) {
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	vols := map[string]VolumeConf{
		"s3":  {Endpoint: "https://s3.example.org", Bucket: "bits", Region: "r", AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"},
		"pub": {Endpoint: "https://s3.example.org", Bucket: "open", Region: "r"}}
	for name, c := range map[string]struct {
		b  Binding
		ok bool
	}{
		"public":    {Binding{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git", Public: true}, true},
		"private":   {Binding{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git"}, true},
		"anonymous": {Binding{Prefix: "/git", Volume: "pub", KeyPrefix: "GIT", Format: "git", Public: true}, false},
		"max_size":  {Binding{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git", MaxSize: 1}, false},
		"index":     {Binding{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git", Index: "https://x/simple"}, false},
	} {
		_, err := New(&Config{Issuer: "i", Audience: "a", Keys: map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
			Volumes: vols, Bindings: []Binding{c.b}})
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// A repository upstream does not have is not made: nothing kept for a wrong path.
func TestGitNoSuchRepository(t *testing.T) {
	t.Setenv("TEST_AK", "a")
	t.Setenv("TEST_SK", "s")
	anyAddr(t)
	defer func(s string) { gitScheme = s }(gitScheme)
	gitScheme = "http"
	up := newGitUpstream(t)
	s, err := New(&Config{Issuer: "i", Audience: "a", Keys: map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
		Volumes: map[string]VolumeConf{"s3": {Endpoint: "https://s3.example.org", Bucket: "bits", Region: "r",
			AccessKeyEnv: "TEST_AK", SecretKeyEnv: "TEST_SK"}},
		Bindings: []Binding{{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git", Public: true}}})
	if err != nil {
		t.Fatal(err)
	}
	s.git.root = t.TempDir()
	store := httptest.NewServer(s)
	t.Cleanup(store.Close)
	host := strings.TrimPrefix(up.srv.URL, "http://")
	if out, err := gitIn(t.TempDir(), "ls-remote", store.URL+"/git/"+host+"/none"); err == nil {
		t.Fatalf("a repository upstream has not: %s", out)
	}
	if _, err := os.Stat(filepath.Join(s.git.root, "GIT", host, "none.git")); !os.IsNotExist(err) {
		t.Fatalf("kept: %v", err)
	}
}
