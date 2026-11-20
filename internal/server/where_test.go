// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// Where a list of folders' first objects are, in one question; only POST asks it.
func TestAdminWhere(t *testing.T) {
	s, _, x, _ := gcSetup(t)
	at, ctx := s.place["s3"], context.Background()
	for _, k := range []string{"TT/el9/store/aa/aaaa/x.tar.gz", "TT/el9/store/aa/aaaa/y.tar.gz",
		"TT/el9/store/aa/aaaab/z.tar.gz", "TT/el9/store/aa/aaaa/z/1", "TT/el9/store/aa/aaaa/z/2"} {
		x.Put(ctx, at, index.Object{Key: k, Size: 1, ETag: "e", Mtime: s.now()}, s.now())
	}
	tars := "/store/lhcb/x86_64-el10-gcc14-opt/t"
	ask := func(method, body string, caps ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/_admin/where", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+adminToken(t, s, "admin:alice", time.Minute, caps...))
		w := httptest.NewRecorder()
		s.ServeAdmin(w, r)
		return w
	}
	look := func(ls ...[2]string) string {
		var parts []string
		for _, l := range ls {
			parts = append(parts, fmt.Sprintf(`{"binding": %q, "under": %q}`, l[0], l[1]))
		}
		return `{"look": [` + strings.Join(parts, ", ") + `]}`
	}
	w := ask("POST", look([2]string{tars, "el9/store/aa/aaaa/"}, [2]string{tars, "el9/store/aa/aaa"},
		[2]string{"/nowhere", "x"}, [2]string{tars, "el9/store/zz"}), "POST /_admin/where")
	var a struct{ Found [][]ObjectRow }
	if err := json.Unmarshal(w.Body.Bytes(), &a); w.Code != 200 || err != nil || len(a.Found) != 4 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var got []string
	for _, r := range a.Found[0] {
		got = append(got, r.Key)
	}
	if strings.Join(got, " ") != "TT/el9/store/aa/aaaa/x.tar.gz TT/el9/store/aa/aaaa/y.tar.gz TT/el9/store/aa/aaaa/z/1" {
		t.Errorf("under aaaa/, the first %d: %v", whereRows, got)
	}
	if a.Found[0][0].Hash != "aaaa" || a.Found[0][0].Arch != "el9" {
		t.Errorf("a package's row: %+v", a.Found[0][0])
	}
	if a.Found[1] == nil || len(a.Found[1]) != 0 || a.Found[2] != nil || len(a.Found[3]) != 0 {
		t.Errorf("a folder's name cut short, a binding not configured, nothing there: %s", w.Body)
	}
	many := strings.Repeat(`{"binding": "/x", "under": "y"}, `, whereLooks) + `{"binding": "/x", "under": "y"}`
	for name, body := range map[string]string{"no folder": look([2]string{tars, ""}), "a dot folder": look([2]string{tars, "a/../b"}),
		"an unknown field": `{"look": [], "more": 1}`, "too many": `{"look": [` + many + `]}`, "not JSON": "{"} {
		if w := ask("POST", body, "POST /_admin/where"); w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if w := ask("GET", "", "GET /_admin/**"); w.Code != 405 || w.Header().Get("Allow") != "POST" {
		t.Errorf("GET: %d %q", w.Code, w.Header().Get("Allow"))
	}
	if w := ask("PUT", look(), "PUT /_admin/**"); w.Code != 405 {
		t.Errorf("PUT: %d", w.Code)
	}
	if w := ask("POST", look(), "GET /_admin/**", "PUT /_admin/**"); w.Code != 403 {
		t.Errorf("without POST: %d", w.Code)
	}
	if w := ask("POST", look(), "POST /_admin/**"); w.Code != 200 || !strings.Contains(w.Body.String(), `"found":[]`) {
		t.Errorf("nothing asked: %d %s", w.Code, w.Body)
	}
	for _, p := range []string{"/_admin/objects", "/_admin/withdraw"} { // a view, an action
		r := httptest.NewRequest("POST", p, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+adminToken(t, s, "admin:alice", time.Minute, "POST /_admin/**"))
		w := httptest.NewRecorder()
		if s.ServeAdmin(w, r); w.Code != 405 {
			t.Errorf("POST %s: %d", p, w.Code)
		}
	}
}
