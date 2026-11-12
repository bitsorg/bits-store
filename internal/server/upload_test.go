// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory bucket. Its "upload" stands in for the client's PUT
// to the presigned URL.
type memStore struct {
	delay      time.Duration // a slow copy widens the window between HEAD and copy
	silentFail bool          // the copy reports success but writes nothing (200 with an error body)
	beforeCopy func()        // runs just before the copy, e.g. to swap the staged bytes
	noIfMatch  bool          // the backend ignores x-amz-copy-source-if-match
	copyFails  bool          // the copy errors and writes nothing (it may still land later)
	statFails  string        // Stat of this key fails once
	mu         sync.Mutex
	objs       map[string][]byte
	meta       map[string]map[string]string
	parted     map[string]bool // copied in parts: its ETag is not its MD5
}

func newMem() *memStore {
	return &memStore{objs: map[string][]byte{}, meta: map[string]map[string]string{}, parted: map[string]bool{}}
}
func (m *memStore) Anonymous() bool { return false }
func (m *memStore) Presign(_ context.Context, method, key string, _ time.Duration, hdr http.Header) (string, error) {
	return fmt.Sprintf("https://mem/%s?m=%s&md5=%s", key, method, hdr.Get("Content-MD5")), nil
}
func (m *memStore) Stat(ctx context.Context, key string) (objInfo, bool, error) {
	if ctx.Err() != nil {
		return objInfo{}, false, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if key == m.statFails {
		m.statFails = ""
		return objInfo{}, false, fmt.Errorf("stat failed")
	}
	b, ok := m.objs[key]
	sum := md5.Sum(b)
	etag := hex.EncodeToString(sum[:])
	if m.parted[key] {
		etag = fmt.Sprintf("%x-2", md5.Sum(sum[:]))
	}
	return objInfo{int64(len(b)), etag, m.meta[key]}, ok, nil
}
func (m *memStore) Copy(_ context.Context, src, srcETag, dst string, size int64, meta map[string]string) error {
	time.Sleep(m.delay)
	if m.beforeCopy != nil {
		m.beforeCopy()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.silentFail {
		return nil
	}
	if m.copyFails {
		return fmt.Errorf("timeout")
	}
	if sum := md5.Sum(m.objs[src]); !m.noIfMatch && hex.EncodeToString(sum[:]) != srcETag {
		return fmt.Errorf("precondition failed") // x-amz-copy-source-if-match
	}
	m.objs[dst], m.meta[dst], m.parted[dst] = m.objs[src], meta, size > maxCopy
	return nil
}
func (m *memStore) Remove(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, key)
	return nil
}
func (m *memStore) upload(key string, b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[key] = b
}
func (m *memStore) has(key string) bool { _, ok, _ := m.Stat(context.Background(), key); return ok }

type started struct {
	ID, URL, Method string
	Headers         map[string]string
}

func body(b []byte) string {
	s, m := sha256.Sum256(b), md5.Sum(b)
	return fmt.Sprintf(`{"size": %d, "md5": %q, "sha256": %q}`, len(b), base64.StdEncoding.EncodeToString(m[:]), hex.EncodeToString(s[:]))
}

func post(s *Server, target, tok, b string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", target, strings.NewReader(b))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func start(t *testing.T, s *Server, path, tok string, data []byte) started {
	w := post(s, path+"?uploads", tok, body(data))
	if w.Code != 201 {
		t.Fatalf("start %s: %d %s", path, w.Code, w.Body)
	}
	var st started
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || st.Method != "PUT" || st.Headers["Content-MD5"] == "" ||
		!strings.Contains(st.URL, "/STAGING/"+st.ID+"?") {
		t.Fatalf("start %s: %s", path, w.Body)
	}
	return st
}

// The vectors' first token may PUT /store/lhcb/x86_64-el10-gcc14-opt/**, GET only elsewhere.
const final = "/store/lhcb/x86_64-el10-gcc14-opt/ab/h"
const finalKey = "TARS/x86_64-el10-gcc14-opt/ab/h"

func TestUploadPromotes(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("package tarball")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d", w.Code)
	}
	sum := sha256.Sum256(data)
	if string(m.objs[finalKey]) != string(data) || m.meta[finalKey]["declared-sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatal("not promoted with its sha256")
	}
	if m.has("STAGING/" + st.ID) {
		t.Fatal("staging object left behind")
	}
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("retried complete: %d", w.Code)
	}
	if w := post(s, final+"?uploads", tok, body(data)); w.Code != 409 {
		t.Fatalf("start over an existing object: %d", w.Code)
	}
}

// Above maxCopy a promote copies in parts: the final ETag is no MD5, its upload id says it is ours.
func TestALargeUploadIsPromotedInParts(t *testing.T) {
	old := maxCopy
	maxCopy = 8
	defer func() { maxCopy = old }()
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("a large package tarball")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	if !m.parted[finalKey] || m.meta[finalKey]["bits-upload"] != st.ID {
		t.Fatalf("not copied in parts with its upload id: %v %v", m.parted[finalKey], m.meta[finalKey])
	}
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("retried complete: %d", w.Code)
	}
	// a copy that outlasts the step timeout is settled with a fresh one
	oldStep := stepTimeout
	stepTimeout = 50 * time.Millisecond
	defer func() { stepTimeout = oldStep }()
	m.delay = 100 * time.Millisecond
	st = start(t, s, final+"slow", tok, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"slow?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("a slow copy: %d %s", w.Code, w.Body)
	}
	m.delay = 0
	// an object of that size someone else copied in parts, there by the complete, is not ours
	st = start(t, s, final+"2", tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.objs[finalKey+"2"], m.parted[finalKey+"2"] = data, true
	if w := post(s, final+"2?complete="+st.ID, tok, ""); w.Code != 409 {
		t.Fatalf("another's object of the same size: %d %s", w.Code, w.Body)
	}
	for i, other := range []struct {
		size int64             // maxCopy for the upload: above it, the id is asked
		meta map[string]string // the object found at the name
	}{{8, map[string]string{"bits-upload": "another-id"}}, {64, nil}} {
		maxCopy = other.size
		name := fmt.Sprintf("%s-o%d", final, i)
		st = start(t, s, name, tok, data)
		m.upload("STAGING/"+st.ID, data)
		k := fmt.Sprintf("%s-o%d", finalKey, i)
		meta := other.meta
		if meta == nil { // our id, but not parted, and its ETag not our MD5
			meta = map[string]string{"bits-upload": st.ID}
		}
		m.objs[k], m.parted[k], m.meta[k] = data, true, meta
		if w := post(s, name+"?complete="+st.ID, tok, ""); w.Code != 409 {
			t.Fatalf("case %d, not ours: %d %s", i, w.Code, w.Body)
		}
	}
}

func TestUploadRefusals(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("package tarball")

	st := start(t, s, final, tok, data)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 409 || !strings.Contains(w.Body.String(), `"not-uploaded"`) {
		t.Errorf("complete before the upload: %d", w.Code)
	}
	m.upload("STAGING/"+st.ID, []byte("other bytes"))
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 422 || m.has(finalKey) || m.has("STAGING/"+st.ID) {
		t.Errorf("wrong bytes: %d, promoted %v", w.Code, m.has(finalKey))
	}
	st = start(t, s, final, tok, data)
	if w := post(s, "/store/lhcb/x86_64-el10-gcc14-opt/ab/other?complete="+st.ID, tok, ""); w.Code != 404 {
		t.Errorf("complete under another name: %d", w.Code)
	}
	// first writer wins: the object appears between start and complete
	m.upload(finalKey, []byte("first"))
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 409 || string(m.objs[finalKey]) != "first" {
		t.Errorf("overwrite: %d", w.Code)
	}
	for name, c := range map[string]struct {
		target, body string
		code         int
	}{
		"get-only-capability": {"/sources/archives/x?uploads", body(data), 403},
		"bad-json":            {final + "x?uploads", `{"size": 1}`, 400},
		"unknown-field":       {final + "x?uploads", `{"size": 1, "md5": "", "sha256": "", "x": 1}`, 400},
		"too-large":           {final + "x?uploads", strings.Replace(body(data), fmt.Sprintf(`"size": %d`, len(data)), `"size": 6000000000`, 1), 400},
		"no-action":           {final + "x", body(data), 400},
		"two-actions":         {final + "x?uploads&complete=a", body(data), 400},
		"unknown-id":          {final + "x?complete=nope", "", 404},
	} {
		if w := post(s, c.target, tok, c.body); w.Code != c.code {
			t.Errorf("%s: want %d, got %d", name, c.code, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/public/a?uploads", strings.NewReader(body(data)))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 && w.Code != 405 {
		t.Errorf("write to a public binding: %d", w.Code)
	}
}

func TestUploadExpires(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("x")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	s.uploads.m[st.ID].expires = now.Add(-time.Second)
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 404 || m.has(finalKey) {
		t.Fatalf("expired upload completed: %d", w.Code)
	}
}

func TestOnlyItsOwnerCompletes(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	other := tokenNamed(t, "build-key-build-sub") // same capabilities, sub build:123
	data := []byte("x")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	if w := post(s, final+"?complete="+st.ID, other, ""); w.Code != 404 || m.has(finalKey) {
		t.Fatalf("another subject completed it: %d", w.Code)
	}
}

func TestConcurrentCompletes(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	m.delay = 20 * time.Millisecond
	ids := make([]string, 8)
	for i := range ids {
		data := []byte(fmt.Sprintf("build %d", i))
		ids[i] = start(t, s, final, tok, data).ID
		m.upload("STAGING/"+ids[i], data)
	}
	codes := make(chan int, len(ids))
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			codes <- post(s, final+"?complete="+id, tok, "").Code
		}(id)
	}
	wg.Wait()
	close(codes)
	won := 0
	for c := range codes {
		if c == 201 {
			won++
		} else if c != 409 {
			t.Errorf("unexpected %d", c)
		}
	}
	if won != 1 {
		t.Fatalf("%d uploads promoted to one name", won)
	}
}

func TestCopyIsSettledByTheFinalObject(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("package tarball")

	// staged bytes swapped after the check: the conditional copy refuses
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.beforeCopy = func() { m.upload("STAGING/"+st.ID, []byte("swapped")) }
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code == 201 || m.has(finalKey) {
		t.Fatalf("swapped bytes promoted: %d", w.Code)
	}
	s.now = func() time.Time { return now.Add(copyTimeout + time.Second) } // the refused copy held the name
	// ... and where the backend ignores the condition, the check after the copy
	st = start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.noIfMatch = true
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 422 || m.has(finalKey) {
		t.Fatalf("swapped bytes promoted without if-match: %d", w.Code)
	}
	m.beforeCopy, m.noIfMatch = nil, false

	// a copy that says yes but wrote nothing: 502, staging kept for a retry
	st = start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.silentFail = true
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 502 || !m.has("STAGING/"+st.ID) {
		t.Fatalf("silent copy failure: %d", w.Code)
	}
	m.silentFail = false
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 || !m.has(finalKey) {
		t.Fatalf("retry after a failed copy: %d", w.Code)
	}
}

func TestLimits(t *testing.T) {
	s, tok, now := setup(t)
	s.stores["s3"] = newMem()
	for i := 0; i < maxPerSubject; i++ {
		start(t, s, fmt.Sprintf("%s-%d", final, i), tok, []byte("x"))
	}
	if w := post(s, final+"-last?uploads", tok, body([]byte("x"))); w.Code != 503 {
		t.Errorf("subject over its share: %d", w.Code)
	}
	other := tokenNamed(t, "build-key-build-sub")
	if w := post(s, final+"-other?uploads", other, body([]byte("x"))); w.Code != 201 {
		t.Errorf("another subject blocked: %d", w.Code)
	}
	s.now = func() time.Time { return now.Add(3600*time.Second - 30*time.Second) } // token: 30 s left
	if w := post(s, final+"-late?uploads", other, body([]byte("x"))); w.Code != 401 {
		t.Errorf("start with a token about to expire: %d", w.Code)
	}
}

func TestLostAnswerAndHeldLease(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("package tarball")

	// the copy lands but the check after it fails: 502, then the retry gets 201
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.beforeCopy = func() { m.statFails = finalKey }
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 502 {
		t.Fatalf("lost answer: %d", w.Code)
	}
	m.beforeCopy = nil
	s.now = func() time.Time { return now.Add(copyTimeout + time.Second) } // past the hold
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 || m.has("STAGING/"+st.ID) {
		t.Fatalf("retry after a lost answer: %d %s", w.Code, w.Body)
	}
	s.now = func() time.Time { return now }

	// a copy that errored may still land: the name stays leased for copyTimeout
	other := final + "-held"
	st = start(t, s, other, tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.copyFails = true
	if w := post(s, other+"?complete="+st.ID, tok, ""); w.Code != 502 {
		t.Fatalf("failed copy: %d", w.Code)
	}
	m.copyFails = false
	if w := post(s, other+"?complete="+st.ID, tok, ""); w.Code != 409 || !strings.Contains(w.Body.String(), `"busy"`) {
		t.Fatalf("complete during the hold: %d %s", w.Code, w.Body)
	}
	s.now = func() time.Time { return now.Add(copyTimeout + time.Second) }
	if w := post(s, other+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete after the hold: %d %s", w.Code, w.Body)
	}
}

func TestForeignObjectLeftAlone(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("package tarball")
	st := start(t, s, final, tok, data)
	m.upload("STAGING/"+st.ID, data)
	m.beforeCopy = func() { // another writer, and the staged bytes swapped: the copy is refused
		m.upload(finalKey, []byte("foreign"))
		m.upload("STAGING/"+st.ID, []byte("swapped"))
	}
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 409 || string(m.objs[finalKey]) != "foreign" {
		t.Fatalf("foreign object: %d, final %q", w.Code, m.objs[finalKey])
	}
}

func TestFinishedUploadsDoNotFillTheTable(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	for i := 0; i < maxPerSubject+5; i++ {
		p, data := fmt.Sprintf("%s-%d", final, i), []byte(fmt.Sprint(i))
		st := start(t, s, p, tok, data)
		m.upload("STAGING/"+st.ID, data)
		if w := post(s, p+"?complete="+st.ID, tok, ""); w.Code != 201 {
			t.Fatalf("%d: %d", i, w.Code)
		}
	}
}
