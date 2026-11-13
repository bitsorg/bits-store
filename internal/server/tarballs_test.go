// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tarHash = "0123456789abcdef0123456789abcdef01234567"
	tarPath = "/store/lhcb/x86_64-el10-gcc14-opt/t/x86_64-el9/" + tarHash
	tarDir  = "TT/x86_64-el9/store/01/" + tarHash
	tarName = "ROOT-6.32.02-1.x86_64-el9.tar.gz"
)

// named declares data under a name, as a tarballs upload does.
func named(name string, data []byte) string {
	var m map[string]any
	json.Unmarshal([]byte(body(data)), &m)
	m["name"] = name
	b, _ := json.Marshal(m)
	return string(b)
}

func startNamed(t *testing.T, s *Server, tok, name string, data []byte) started {
	w := post(s, tarPath+"?uploads", tok, named(name, data))
	var st started
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &st) != nil || !strings.Contains(st.URL, "/STAGING/"+st.ID+"?") {
		t.Fatalf("start %s: %d %s", name, w.Code, w.Body)
	}
	return st
}

func TestTarballByHash(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	auth := map[string]string{"Authorization": "Bearer " + tok}
	if w := do(s, "GET", tarPath, nil); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(s, "GET", tarPath, auth); w.Code != 404 {
		t.Fatalf("nothing stored: %d", w.Code)
	}
	data := []byte("tarball")
	st := startNamed(t, s, tok, tarName, data)
	m.upload("STAGING/"+st.ID, data)
	for range 2 { // a retry after a lost answer is a success too
		if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 201 {
			t.Fatalf("complete: %d %s", w.Code, w.Body)
		}
	}
	if string(m.objs[tarDir+"/"+tarName]) != "tarball" {
		t.Fatalf("not stored under its name: %v", m.objs)
	}
	for _, method := range []string{"GET", "HEAD"} {
		w := do(s, method, tarPath, auth)
		if w.Code != 302 || w.Header().Get("Bits-Object-Name") != tarName ||
			!strings.Contains(w.Header().Get("Location"), "/"+tarDir+"/"+tarName+"?m="+method) {
			t.Fatalf("%s: %d %v", method, w.Code, w.Header())
		}
	}
}

func TestTarballFirstWriterWins(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	other := "ROOT-6.32.02-2.x86_64-el9.tar.gz"
	// another name appears between start and complete
	st := startNamed(t, s, tok, tarName, []byte("mine"))
	m.upload("STAGING/"+st.ID, []byte("mine"))
	m.upload(tarDir+"/"+other, []byte("first"))
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 409 || m.has(tarDir+"/"+tarName) || m.has("STAGING/"+st.ID) {
		t.Fatalf("complete under another name: %d %s", w.Code, w.Body)
	}
	if w := post(s, tarPath+"?uploads", tok, named(tarName, []byte("mine"))); w.Code != 409 {
		t.Fatalf("start over another name: %d", w.Code)
	}
	// two objects under one hash (old stores): the lowest revision, by number
	m.upload(tarDir+"/ROOT-6.32.02-10.x86_64-el9.tar.gz", []byte("tenth"))
	m.upload(tarDir+"/sub/a.x86_64-el9.tar.gz", []byte("not in the folder"))
	w := do(s, "GET", tarPath, map[string]string{"Authorization": "Bearer " + tok})
	if w.Code != 302 || w.Header().Get("Bits-Object-Name") != other {
		t.Fatalf("two objects: %d %v", w.Code, w.Header())
	}
}

func TestTarballNamesRacing(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	m.delay = 20 * time.Millisecond // both completes overlap
	var ids []string
	for _, name := range []string{tarName, "ROOT-6.32.02-2.x86_64-el9.tar.gz"} {
		st := startNamed(t, s, tok, name, []byte(name))
		m.upload("STAGING/"+st.ID, []byte(name))
		ids = append(ids, st.ID)
	}
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = post(s, tarPath+"?complete="+id, tok, "").Code
		}()
	}
	wg.Wait()
	slices.Sort(codes)
	n := 0
	for k := range m.objs {
		if strings.HasPrefix(k, tarDir+"/") {
			n++
		}
	}
	if codes[0] != 201 || codes[1] != 409 || n != 1 {
		t.Fatalf("two names at once: %v, %d stored", codes, n)
	}
	// a complete through another hash's path is not this upload's
	other := strings.Replace(tarPath, tarHash, strings.Repeat("ab", 20), 1)
	w := post(s, other+"?uploads", tok, named(tarName, []byte("x")))
	var st started
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &st) != nil {
		t.Fatalf("start on another hash: %d %s", w.Code, w.Body)
	}
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 404 {
		t.Fatalf("complete through another hash: %d", w.Code)
	}
}

func TestTarballReadsAreCached(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	auth := map[string]string{"Authorization": "Bearer " + tok}
	do(s, "GET", tarPath, auth)
	do(s, "GET", tarPath, auth)
	if m.listed != 1 {
		t.Fatalf("a miss listed %d times", m.listed)
	}
	st := startNamed(t, s, tok, tarName, []byte("x")) // writes list for themselves
	m.upload("STAGING/"+st.ID, []byte("x"))
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d", w.Code)
	}
	if w := do(s, "GET", tarPath, auth); w.Code != 302 {
		t.Fatalf("after storing it here, the cached miss stood: %d", w.Code)
	}
	listed := m.listed
	do(s, "HEAD", tarPath, auth)
	if m.listed != listed {
		t.Fatal("a hit listed again")
	}
}

func TestTarballLeaseIsTheFolder(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	st := startNamed(t, s, tok, tarName, []byte("x"))
	m.upload("STAGING/"+st.ID, []byte("x"))
	s.uploads.lease(s.place["s3"], tarDir+"/", now) // another name being promoted
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 409 || !strings.Contains(w.Body.String(), "busy") {
		t.Fatalf("while another promotes: %d %s", w.Code, w.Body)
	}
}

func TestTarballRefusals(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("x")
	for name, c := range map[string]struct {
		target, body string
		code         int
	}{
		"other-arch":    {tarPath + "?uploads", named("ROOT-1-1.x86_64-el8.tar.gz", data), 400},
		"no-name":       {tarPath + "?uploads", body(data), 400},
		"slash":         {tarPath + "?uploads", named("a/ROOT-1-1.x86_64-el9.tar.gz", data), 400},
		"bad-chars":     {tarPath + "?uploads", named("ROOT 1.x86_64-el9.tar.gz", data), 400},
		"name-for-blob": {final + "?uploads", named(tarName, data), 400},
		"short-hash":    {"/store/lhcb/x86_64-el10-gcc14-opt/t/x86_64-el9/0123?uploads", named(tarName, data), 404},
	} {
		if w := post(s, c.target, tok, c.body); w.Code != c.code {
			t.Errorf("%s: want %d, got %d %s", name, c.code, w.Code, w.Body)
		}
	}
	m.listFails = true
	if w := do(s, "GET", tarPath, map[string]string{"Authorization": "Bearer " + tok}); w.Code != 502 {
		t.Errorf("list fails: %d", w.Code)
	}
	if w := post(s, tarPath+"?uploads", tok, named(tarName, data)); w.Code != 502 {
		t.Errorf("list fails at start: %d", w.Code)
	}
	m.listFails = false
	st := startNamed(t, s, tok, tarName, data)
	m.upload("STAGING/"+st.ID, data)
	m.listFails = true
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 502 || m.has(tarDir+"/"+tarName) {
		t.Errorf("list fails at complete: %d", w.Code)
	}
}

func TestPublicTarballs(t *testing.T) {
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	key := "PUBT/x86_64-el9/store/01/" + tarHash + "/" + tarName
	m.upload(key, []byte("public"))
	pub := "/store/lhcb/x86_64-el10-gcc14-opt/pt/x86_64-el9/" + tarHash
	for _, method := range []string{"GET", "HEAD"} {
		w := do(s, method, pub, nil)
		if w.Code != 302 || w.Header().Get("Location") != "https://s3.example.org/bits/"+key || w.Header().Get("Bits-Object-Name") != tarName {
			t.Fatalf("anonymous %s: %d %v", method, w.Code, w.Header())
		}
	}
	// a public binding with keys takes a token's writes; anyone reads them
	if w := post(s, pub+"?uploads", tok, named(tarName, []byte("x"))); w.Code != 409 {
		t.Fatalf("write over the stored build: %d", w.Code)
	}
	other := strings.Replace(pub, tarHash, strings.Repeat("cd", 20), 1)
	w := post(s, other+"?uploads", tok, named(tarName, []byte("new")))
	var st started
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &st) != nil {
		t.Fatalf("write to a public binding: %d %s", w.Code, w.Body)
	}
	m.upload("STAGING/"+st.ID, []byte("new"))
	if w := post(s, other+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d", w.Code)
	}
	newKey := "PUBT/x86_64-el9/store/cd/" + strings.Repeat("cd", 20) + "/" + tarName
	if sum := sha256.Sum256([]byte("new")); m.meta[newKey]["sha256"] != "sha256:"+hex.EncodeToString(sum[:]) || m.meta[newKey]["declared-sha256"] != "" {
		t.Fatalf("a build's sha256 not under bits' name: %v", m.meta[newKey])
	}
	if w := do(s, "GET", other, nil); w.Code != 302 {
		t.Fatalf("anonymous read of it: %d", w.Code)
	}
	if w := post(s, other+"?uploads", "", named(tarName, []byte("x"))); w.Code != 401 {
		t.Fatalf("a write without a token: %d", w.Code)
	}
}

// A read that listed before this instance stored the object must not leave a miss.
func TestTarballStaleMissIsNotKept(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	m.afterList = func() {
		m.upload(tarDir+"/"+tarName, []byte("x"))
		s.found.stored(s, "s3", tarDir, tarDir+"/"+tarName, now)
	}
	auth := map[string]string{"Authorization": "Bearer " + tok}
	if w := do(s, "GET", tarPath, auth); w.Code != 404 {
		t.Fatalf("the read that listed first: %d", w.Code)
	}
	if w := do(s, "GET", tarPath, auth); w.Code != 302 {
		t.Fatalf("after the store: %d", w.Code)
	}
}

// The copy landed but its answer was lost: the retry finds its own file, not another.
func TestTarballLostAnswer(t *testing.T) {
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	st := startNamed(t, s, tok, tarName, []byte("x"))
	m.upload("STAGING/"+st.ID, []byte("x"))
	m.beforeCopy = func() { m.statFails = tarDir + "/" + tarName }
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 502 {
		t.Fatalf("lost answer: %d", w.Code)
	}
	m.beforeCopy = nil
	s.now = func() time.Time { return now.Add(copyTimeout + time.Second) } // past the hold
	if w := post(s, tarPath+"?complete="+st.ID, tok, ""); w.Code != 201 {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
}

func TestAnAnonymousVolumeTakesNoWrites(t *testing.T) {
	s, tok, _ := setup(t)
	s.stores["s3"] = newMem()
	if w := post(s, "/store/lhcb/x86_64-el10-gcc14-opt/anon/x?uploads", tok, body([]byte("x"))); w.Code != 405 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
