// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMetrics(t *testing.T) {
	s, _, now := setup(t)
	if w := do(s, "GET", "/metrics", nil); w.Code != 404 {
		t.Fatalf("without an index: %d", w.Code)
	}
	m := newMem()
	s.stores["s3"], s.stores["s3-too"], s.place["s3-too"] = m, m, s.place["s3"] // one bucket, two names
	x := withIndex(t, s)
	m.objs["TT/el9/store/ab/abc/a-1-1.el9.tar.gz"] = []byte("1234567890")
	m.objs["PUBT/el9/store/cd/cde/b-1-1.el9.tar.gz"] = []byte("12345")
	m.objs["PUBT/el10/store/cd/cde/b-1-1.el10.tar.gz"] = []byte("123")
	m.objs["MM/rev-index/el9/a/1-1"] = []byte("abc") // not a tarballs prefix
	m.objs["TT/a\"b\\c\td/x"] = []byte("1")          // quoted as the text format has it
	m.objs["LOOSE/u1"] = []byte("1234")            // under no binding
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
	if get() != body {
		t.Fatal("not the cached answer")
	}
	clock = clock.Add(metricsEvery)
	if w := do(s, "GET", "/metrics", nil); w.Code != 500 {
		t.Fatalf("a failing index: %d", w.Code)
	}
}
