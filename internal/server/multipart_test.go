// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// partsBody declares data in parts of partSize.
func partsBody(data []byte, partSize int) string {
	var sums []string
	for off := 0; off < len(data); off += partSize {
		sum := md5.Sum(data[off:min(off+partSize, len(data))])
		sums = append(sums, base64.StdEncoding.EncodeToString(sum[:]))
	}
	sh := sha256.Sum256(data)
	b, _ := json.Marshal(map[string]any{"size": len(data), "sha256": hex.EncodeToString(sh[:]),
		"part_size": partSize, "part_md5": sums})
	return string(b)
}

type startedParts struct {
	ID, Method string
	URL        string
	Parts      []struct {
		Number  int
		URL     string
		Headers map[string]string
	}
}

func startParts(t *testing.T, s *Server, path, tok, b string) startedParts {
	w := post(s, path+"?uploads", tok, b)
	var st startedParts
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &st) != nil || st.URL != "" || st.Method != "PUT" {
		t.Fatalf("start in parts: %d %s", w.Code, w.Body)
	}
	return st
}

// uploadID is the multipart upload id a part URL names.
func uploadID(u string) string {
	_, rest, _ := strings.Cut(u, "uploadId=")
	id, _, _ := strings.Cut(rest, "&")
	return id
}

func TestUploadInParts(t *testing.T) {
	defer func(c int64) { maxCopy = c }(maxCopy)
	for _, mc := range []int64{maxCopy, 1 << 20} { // a plain copy, then one in parts
		maxCopy = mc
		s, tok, _ := setup(t)
		m := newMem()
		s.stores["s3"] = m
		data := bytes.Repeat([]byte("0123456789abcdef"), (11<<20)/16+3) // 11 MiB and 48 bytes
		st := startParts(t, s, final, tok, partsBody(data, 5<<20))
		if len(st.Parts) != 3 {
			t.Fatalf("%d parts", len(st.Parts))
		}
		for i, p := range st.Parts {
			sum := md5.Sum(data[i*(5<<20) : min((i+1)*(5<<20), len(data))])
			if p.Number != i+1 || !strings.Contains(p.URL, fmt.Sprintf("partNumber=%d&", i+1)) ||
				!strings.HasSuffix(p.URL, "md5="+p.Headers["Content-MD5"]) || // signed in the URL
				p.Headers["Content-MD5"] != base64.StdEncoding.EncodeToString(sum[:]) {
				t.Fatalf("part %d: %+v", i+1, p)
			}
		}
		id := uploadID(st.Parts[0].URL)
		complete := func() int { return post(s, final+"?complete="+st.ID, tok, "").Code }
		m.uploadPart(id, 1, data[:5<<20])
		m.uploadPart(id, 2, data[5<<20:9<<20]) // short
		if c := complete(); c != 409 {
			t.Fatalf("parts missing or short: %d", c)
		}
		m.uploadPart(id, 2, data[5<<20:10<<20])
		m.uploadPart(id, 3, data[10<<20:])
		if c := complete(); c != 201 {
			t.Fatalf("maxCopy %d: complete: %d", mc, c)
		}
		sh := sha256.Sum256(data)
		if !bytes.Equal(m.objs[finalKey], data) || m.meta[finalKey]["declared-sha256"] != hex.EncodeToString(sh[:]) || m.has("STAGING/"+st.ID) {
			t.Fatalf("maxCopy %d: not promoted: %d bytes, %v", mc, len(m.objs[finalKey]), m.meta[finalKey])
		}
		if c := complete(); c != 201 {
			t.Fatalf("a retried complete: %d", c)
		}
	}
}

func TestUploadInPartsRefusals(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := bytes.Repeat([]byte("x"), 6<<20)
	good := partsBody(data, 5<<20)
	var decl map[string]any
	json.Unmarshal([]byte(good), &decl)
	with := func(k string, v any) string {
		d := map[string]any{}
		for a, b := range decl {
			d[a] = b
		}
		if v == nil {
			delete(d, k)
		} else {
			d[k] = v
		}
		b, _ := json.Marshal(d)
		return string(b)
	}
	for name, b := range map[string]string{
		"part-too-small":  partsBody(data, 1<<20),
		"part-too-large":  with("part_size", 6<<30),
		"wrong-count":     with("part_md5", []string{decl["part_md5"].([]any)[0].(string)}),
		"bad-md5":         with("part_md5", []string{"x", "y"}),
		"md5-and-parts":   with("md5", "AAAAAAAAAAAAAAAAAAAAAA=="),
		"size-only-parts": with("part_md5", nil),
		"part-size-only":  strings.Replace(body(data), "{", `{"part_size": 5242880, `, 1),
		"too-many-parts":  with("size", int64(maxParts+1)*(5<<20)),
		"too-large":       with("size", int64(2<<40)),
	} {
		if w := post(s, final+"?uploads", tok, b); w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// a part with other bytes than declared (a backend not checking Content-MD5)
	st := startParts(t, s, final, tok, good)
	id := uploadID(st.Parts[0].URL)
	m.uploadPart(id, 1, data[:5<<20])
	m.uploadPart(id, 2, bytes.Repeat([]byte("y"), 1<<20))
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 422 || m.mp[id] != nil || m.has(finalKey) {
		t.Fatalf("other bytes: %d, upload kept %v", w.Code, m.mp[id] != nil)
	}
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 404 {
		t.Fatalf("after a mismatch: %d", w.Code)
	}
	// a failed start leaves no upload, in the table or the volume
	m.presignErr = true
	if w := post(s, final+"?uploads", tok, good); w.Code != 502 || len(m.mp) != 0 || len(s.uploads.m) != 0 {
		t.Fatalf("presign failure: %d, %d uploads in the volume, %d in the table", w.Code, len(m.mp), len(s.uploads.m))
	}
	m.presignErr = false
	for i := range maxPerSubject {
		s.uploads.m[fmt.Sprint(i)] = &upload{sub: "alice", expires: now.Add(time.Hour)}
	}
	if w := post(s, final+"?uploads", tok, good); w.Code != 503 || len(m.mp) != 0 {
		t.Fatalf("table full: %d, %d uploads in the volume", w.Code, len(m.mp))
	}
	s.uploads.m = nil
	// an expired upload is aborted when the table is next touched
	st = startParts(t, s, final, tok, good)
	id = uploadID(st.Parts[0].URL)
	s.uploads.m[st.ID].expires = now.Add(-time.Second)
	startParts(t, s, final+"-other", tok, good)
	for i := 0; ; i++ {
		m.mu.Lock()
		_, left := m.mp[id]
		m.mu.Unlock()
		if !left {
			break
		}
		if i > 100 {
			t.Fatal("an expired upload in parts not aborted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUploadInPartsRetries(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := bytes.Repeat([]byte("z"), 6<<20)
	st := startParts(t, s, final, tok, partsBody(data, 5<<20))
	id := uploadID(st.Parts[0].URL)
	m.uploadPart(id, 1, data[:5<<20])
	s.uploads.get(st.ID).expires = now.Add(time.Second) // a complete just in time
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 409 {
		t.Fatalf("a part missing: %d", w.Code)
	}
	if u := s.uploads.get(st.ID); u.expires.Before(now.Add(2 * copyTime(u.size))) {
		t.Fatalf("a complete did not keep its upload: expires %v", u.expires)
	}
	// assembled by an earlier complete whose promote did not happen
	m.uploadPart(id, 2, data[5<<20:])
	if code, _ := s.assemble(context.Background(), s.uploads.get(st.ID), st.ID); code != 0 {
		t.Fatalf("assemble: %d", code)
	}
	if w := post(s, final+"?complete="+st.ID, tok, ""); w.Code != 201 || !bytes.Equal(m.objs[finalKey], data) {
		t.Fatalf("complete after assembly: %d", w.Code)
	}
}
