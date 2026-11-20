// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// Problems are logged and gathered, written to the index, and read by the admin API.
func TestProblems(t *testing.T) {
	s, _, now := setup(t)
	s.problem(levelError, "presign_failed", "k", "presign %s: %v", "k", "denied") // no index: logged only
	withIndex(t, s)
	for range 3 {
		s.errorf("presign_failed", "k", "presign %s: %v", "k", "denied")
	}
	s.warnf("tag_moved", "https://example.org/r", "git %s: a tag moved", "r")
	s.flushProblems(context.Background())
	admin := adminToken(t, s, "admin:alice", time.Minute, "GET /_admin/problems")
	get := func(q string) (int, []index.Problem) {
		w := doAdmin(s, "GET", "/_admin/problems"+q, map[string]string{"Authorization": "Bearer " + admin})
		var got struct{ Problems []index.Problem }
		json.Unmarshal(w.Body.Bytes(), &got)
		return w.Code, got.Problems
	}
	code, ps := get("")
	if code != 200 || len(ps) != 2 {
		t.Fatalf("%d %+v", code, ps)
	}
	byKind := map[string]index.Problem{}
	for _, p := range ps {
		byKind[p.Kind] = p
	}
	if p := byKind["presign_failed"]; p.Count != 3 || p.Level != "error" || p.Subject != "k" || p.Message != "presign k: denied" {
		t.Fatalf("an error seen 3 times: %+v", p)
	}
	if p := byKind["tag_moved"]; p.Level != "warning" || p.LastMs != now.UnixMilli() {
		t.Fatalf("a warning: %+v", p)
	}
	if code, ps := get("?since=" + itoa(now.Add(time.Second).UnixMilli())); code != 200 || len(ps) != 0 {
		t.Fatalf("since later: %d %+v", code, ps)
	}
	if code, _ := get("?limit=0"); code != 400 {
		t.Fatalf("a bad limit: %d", code)
	}
}

// What git http-backend's CGI handler reports is a problem: a backend missing, say.
func TestGitBackendProblem(t *testing.T) {
	s, _, _ := setup(t)
	withIndex(t, s)
	defer func(b string) { gitBackend = b }(gitBackend)
	gitBackend = "/nonexistent/git-http-backend"
	r := httptest.NewRequest("GET", "/git/example.org/r/info/refs?service=git-upload-pack", nil)
	s.gitBackend(httptest.NewRecorder(), r, t.TempDir(), "example.org/r", nil)
	s.flushProblems(context.Background())
	ps, _ := s.index.Problems(context.Background(), 0, 10)
	if len(ps) != 1 || ps[0].Kind != "git_backend" || ps[0].Subject != "example.org/r" {
		t.Fatalf("%+v", ps)
	}
}
