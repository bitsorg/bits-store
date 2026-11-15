// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
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
		`bits_store_objects_total{volume="s3"} 5` + "\n",
		`bits_store_bytes_total{volume="s3"} 22` + "\n",
		`bits_store_index_drift{volume="s3",kind="missing"} 5` + "\n",
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
	x.Close() // the index fails: the answer of the last minute, then 500
	if get() != body {
		t.Fatal("not the cached answer")
	}
	clock = clock.Add(metricsEvery)
	if w := do(s, "GET", "/metrics", nil); w.Code != 500 {
		t.Fatalf("a failing index: %d", w.Code)
	}
}
