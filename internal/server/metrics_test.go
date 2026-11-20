// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMetrics(t *testing.T) {
	s, _, now := setup(t)
	if w := do(s, "GET", "/metrics", nil); w.Code != 200 || strings.Contains(w.Body.String(), "bits_store_bytes_total") ||
		!strings.Contains(w.Body.String(), "\nbits_store_goroutines ") {
		t.Fatalf("without an index: %d, the meters only:\n%s", w.Code, w.Body)
	}
	m := newMem()
	s.stores["s3"], s.stores["s3-too"], s.place["s3-too"] = m, m, s.place["s3"] // one bucket, two names
	x := withIndex(t, s)
	m.objs["TT/el9/store/ab/abc/a-1-1.el9.tar.gz"] = []byte("1234567890")
	m.objs["PUBT/el9/store/cd/cde/b-1-1.el9.tar.gz"] = []byte("12345")
	m.objs["PUBT/el10/store/cd/cde/b-1-1.el10.tar.gz"] = []byte("123")
	m.objs["MM/rev-index/el9/a/1-1"] = []byte("abc") // not a tarballs prefix
	m.objs["TT/a\"b\\c\td/x"] = []byte("1")          // quoted as the text format has it
	m.objs["LOOSE/u1"] = []byte("1234")              // under no binding
	// a binding inside another's key prefix, and a git binding's repositories on -data
	s.bindings = append(s.bindings, Binding{Prefix: "/nested", Volume: "s3", KeyPrefix: "TT/el9", Format: "blob"},
		Binding{Prefix: "/git", Volume: "s3", KeyPrefix: "GIT", Format: "git", Public: true})
	s.git.root = t.TempDir()
	for f, n := range map[string]int{"github.com/a/b.git/HEAD": 7, "github.com/a/b.git/objects/pack/p.pack": 100,
		"gitlab.cern.ch/c/d.git/HEAD": 7} {
		p := filepath.Join(s.git.root, "GIT", f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, make([]byte, n), 0o644)
	}
	get := func() string {
		w := do(s, "GET", "/metrics", nil)
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
			t.Fatalf("metrics: %d %s", w.Code, w.Body)
		}
		return w.Body.String()
	}
	if body := get(); strings.Contains(body, `volume="s3"`) || !strings.Contains(body, "\nbits_store_index_errors_total 0\n") {
		t.Fatalf("a bucket never listed counted, or no errors line:\n%s", body)
	}
	x.Put(context.Background(), s.place["s3"], indexObject("TT/el9/store/ef/efg/c-1-1.el9.tar.gz", 100), now.Add(-time.Hour))
	s.verifyDue(context.Background(), map[string]time.Time{}) // the Put above is not in the bucket: extra
	if body := get(); strings.Contains(body, `volume="s3"`) {
		t.Fatal("not the answer of a minute ago")
	}
	clock := now.Add(metricsEvery)
	s.now = func() time.Time { return clock }
	body := get()
	for _, want := range []string{
		"# TYPE bits_store_bytes gauge\n",
		`bits_store_bytes{volume="s3",arch="el9"} 15` + "\n",
		`bits_store_objects{volume="s3",arch="el9"} 2` + "\n",
		`bits_store_bytes{volume="s3",arch="el10"} 3` + "\n",
		`bits_store_bytes{volume="s3",arch="a\"b\\c` + "\t" + `d"} 1` + "\n",
		`bits_store_objects_total{volume="s3"} 6` + "\n",
		`bits_store_bytes_total{volume="s3"} 26` + "\n",
		`bits_store_content_objects{volume="s3",key_prefix="TT",binding="/store/lhcb/x86_64-el10-gcc14-opt/t",format="tarballs"} 1` + "\n",
		`bits_store_content_bytes{volume="s3",key_prefix="TT",binding="/store/lhcb/x86_64-el10-gcc14-opt/t",format="tarballs"} 1` + "\n",
		`bits_store_content_bytes{volume="s3",key_prefix="TT/el9",binding="/nested",format="blob"} 10` + "\n",
		`bits_store_content_objects{volume="s3",key_prefix="PUBT",binding="/store/lhcb/x86_64-el10-gcc14-opt/pt",format="tarballs"} 2` + "\n",
		`bits_store_content_bytes{volume="s3",key_prefix="MM",binding="/store/lhcb/x86_64-el10-gcc14-opt/m",format="manifests"} 3` + "\n",
		`bits_store_content_bytes{volume="s3",key_prefix="GIT",binding="/git",format="git"} 0` + "\n",
		`bits_store_content_objects{volume="s3",key_prefix="",binding="(none)",format=""} 1` + "\n",
		`bits_store_content_bytes{volume="s3",key_prefix="",binding="(none)",format=""} 4` + "\n",
		`bits_store_git_repositories{binding="/git",host="github.com"} 1` + "\n",
		`bits_store_git_bytes{binding="/git",host="github.com"} 107` + "\n",
		`bits_store_git_bytes{binding="/git",host="gitlab.cern.ch"} 7` + "\n",
		"\nbits_store_data_free_bytes ",
		`bits_store_index_drift{volume="s3",kind="missing"} 6` + "\n",
		`bits_store_index_drift{volume="s3",kind="extra"} 1` + "\n",
		`bits_store_index_verified_seconds{volume="s3"} ` + itoa(now.Unix()) + "\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("no %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, `volume="pub"`) || strings.Contains(body, `volume="s3-too"`) {
		t.Fatalf("an anonymous volume, or a bucket twice:\n%s", body)
	}
	var objs, size int64 // the contributions add up to the bucket's total
	for _, l := range strings.Split(body, "\n") {
		if f := strings.Fields(l); len(f) == 2 && strings.HasPrefix(l, `bits_store_content_objects{volume="s3"`) {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			objs += n
		} else if len(f) == 2 && strings.HasPrefix(l, `bits_store_content_bytes{volume="s3"`) {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			size += n
		}
	}
	if objs != 6 || size != 26 {
		t.Fatalf("contributions: %d objects, %d bytes; the bucket: 6, 26", objs, size)
	}
	x.Close() // the index fails: the answer of the last minute, then 500
	fromIndex := func(b string) string { i := strings.Index(b, "# HELP bits_store_requests_total"); return b[:i] }
	if fromIndex(get()) != fromIndex(body) { // the meters, after it, change
		t.Fatal("not the cached answer")
	}
	clock = clock.Add(metricsEvery)
	if w := do(s, "GET", "/metrics", nil); w.Code != 500 {
		t.Fatalf("a failing index: %d", w.Code)
	}
}

// The meters: requests by binding, fills from upstream, refused fetches.
func TestMeters(t *testing.T) {
	s, _, _ := setup(t)
	do(s, "GET", "/store/lhcb/x86_64-el10/a", nil) // a binding, no token
	do(s, "GET", "/nowhere/a", nil)                // no binding
	do(s, "GET", "/health", nil)                   // not counted
	s.meters.fill("sources", 10, nil)
	s.meters.fill("git", 0, errors.New("upstream down"))
	s.meters.refuse("pypi", "full")
	w := do(s, "GET", "/metrics", nil)
	for _, want := range []string{
		`bits_store_requests_total{binding="/store/lhcb/x86_64-el10",format="blob",method="GET",code="401"} 1` + "\n",
		`bits_store_requests_total{binding="(none)",format="",method="GET",code="401"} 1` + "\n",
		`bits_store_request_seconds_bucket{binding="(none)",format="",le="+Inf"} 1` + "\n",
		`bits_store_request_seconds_count{binding="/store/lhcb/x86_64-el10",format="blob"} 1` + "\n",
		"# TYPE bits_store_request_seconds histogram\n",
		`bits_store_fills_total{format="sources",result="ok"} 1` + "\n",
		`bits_store_fills_total{format="git",result="failed"} 1` + "\n",
		`bits_store_fill_bytes_total{format="sources"} 10` + "\n",
		`bits_store_fills_refused_total{format="pypi",reason="full"} 1` + "\n",
		"\nbits_store_fetches_running 0\n",
	} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("no %q in:\n%s", want, w.Body)
		}
	}
	if strings.Contains(w.Body.String(), `binding="(none)",format="",method="GET",code="200"`) {
		t.Fatalf("/health or /metrics counted:\n%s", w.Body)
	}
	if !strings.Contains(w.Body.String(), `bits_store_response_bytes_total{binding="(none)",format=""} `) ||
		strings.Contains(w.Body.String(), `bits_store_response_bytes_total{binding="(none)",format=""} 0`+"\n") {
		t.Fatalf("a response's bytes not counted:\n%s", w.Body)
	}
}
