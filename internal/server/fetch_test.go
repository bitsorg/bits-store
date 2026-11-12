// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// origin serves data at /dl/pkg-1.0.tar.gz, counting requests; gate, when set,
// holds each answer until closed.
type origin struct {
	*httptest.Server
	hits   atomic.Int32
	status int
	data   []byte
	chunk  bool // no Content-Length
	gate   chan struct{}
}

func newOrigin(t *testing.T, data []byte) *origin {
	o := &origin{status: 200, data: data}
	o.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		if o.gate != nil {
			<-o.gate
		}
		if r.Header.Get("Accept-Encoding") != "" {
			t.Errorf("Accept-Encoding sent: %q", r.Header.Get("Accept-Encoding"))
		}
		if o.chunk {
			w.Header().Set("Transfer-Encoding", "chunked")
		}
		w.WriteHeader(o.status)
		w.Write(o.data)
		if o.chunk {
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(func() {
		if g := o.gate; g != nil { // a failed test must not leave a handler waiting
			select {
			case <-g:
			default:
				close(g)
			}
		}
		o.Close()
	})
	return o
}

const srcPrefix = "/store/lhcb/x86_64-el10-src"

// srcPath is the sources path of a URL and its object key.
func srcPath(u string) (path, key string) {
	sum := md5.Sum([]byte(u))
	h := hex.EncodeToString(sum[:])
	rest := h[:2] + "/" + h + "/" + u[strings.LastIndex(u, "/")+1:]
	return srcPrefix + "/" + rest, "SRC/" + rest
}

func ask(s *Server, path, src, tok string) *httptest.ResponseRecorder {
	return do(s, "GET", path+"?url="+url.QueryEscape(src), map[string]string{"Authorization": "Bearer " + tok})
}

// allow replaces the address check for a test.
func allow(t *testing.T, f func(netip.Addr) bool) {
	old := fetchAllowed
	fetchAllowed = func(a netip.Addr, _ []netip.Prefix) bool { return f(a) }
	t.Cleanup(func() { fetchAllowed = old })
}

func anyAddr(t *testing.T) { allow(t, func(netip.Addr) bool { return true }) }

// settled waits for the server's fetches to end.
func settled(t *testing.T, s *Server) {
	for i := 0; ; i++ {
		s.fetches.mu.Lock()
		running := 0
		for _, j := range s.fetches.m {
			if j.until.IsZero() {
				running++
			}
		}
		s.fetches.mu.Unlock()
		if running == 0 {
			return
		}
		if i > 500 {
			t.Fatal("a fetch never ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func detail(w *httptest.ResponseRecorder) string {
	var e map[string]string
	json.Unmarshal(w.Body.Bytes(), &e)
	return e["error"] + ": " + e["detail"]
}

func TestFetchServesAMissingSource(t *testing.T) {
	anyAddr(t)
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	data := []byte("source archive")
	o := newOrigin(t, data)
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, key := srcPath(src)
	if w := do(s, "GET", path+"?url="+url.QueryEscape(src), nil); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	w := ask(s, path, src, tok)
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "/"+key+"?") {
		t.Fatalf("first ask: %d %s %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	sum := sha256.Sum256(data)
	if string(m.objs[key]) != string(data) || m.meta[key]["sha256"] != hex.EncodeToString(sum[:]) ||
		m.meta[key]["source-url"] != src {
		t.Fatalf("stored %q with %v", m.objs[key], m.meta[key])
	}
	for k := range m.objs {
		if strings.HasPrefix(k, stagingPrefix) {
			t.Errorf("staging left: %s", k)
		}
	}
	if w := ask(s, path, src, tok); w.Code != 302 || o.hits.Load() != 1 {
		t.Fatalf("second ask: %d, origin asked %d times", w.Code, o.hits.Load())
	}
	if w := do(s, "GET", path, map[string]string{"Authorization": "Bearer " + tok}); w.Code != 302 {
		t.Fatalf("a read without url: %d", w.Code)
	}
}

func TestFetchRefusals(t *testing.T) {
	anyAddr(t)
	s, tok, _ := setup(t)
	s.stores["s3"] = newMem()
	o := newOrigin(t, []byte("x"))
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, _ := srcPath(src)
	for name, target := range map[string]string{
		"another-url":   path + "?url=" + url.QueryEscape(o.URL+"/dl/v2/pkg-1.0.tar.gz"),
		"two-urls":      path + "?url=" + url.QueryEscape(src) + "&url=" + url.QueryEscape(src),
		"another-param": path + "?url=" + url.QueryEscape(src) + "&x=1",
		"no-url":        path + "?x=1",
	} {
		if w := do(s, "GET", target, map[string]string{"Authorization": "Bearer " + tok}); w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if o.hits.Load() != 0 {
		t.Errorf("origin asked %d times", o.hits.Load())
	}
}

func TestFetchOnceForManyAskers(t *testing.T) {
	anyAddr(t)
	defer func(d time.Duration) { fetchWait = d }(fetchWait)
	fetchWait = 50 * time.Millisecond
	s, tok, _ := setup(t)
	s.stores["s3"] = newMem()
	o := newOrigin(t, []byte("slow archive"))
	o.gate = make(chan struct{})
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, _ := srcPath(src)
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := ask(s, path, src, tok); w.Code != 202 || w.Header().Get("Retry-After") == "" {
				t.Errorf("while fetching: %d %v", w.Code, w.Header())
			}
		}()
	}
	wg.Wait()
	close(o.gate)
	for i := 0; ; i++ {
		w := ask(s, path, src, tok)
		if w.Code == 302 {
			break
		}
		if w.Code != 202 || i > 100 {
			t.Fatalf("after the fetch: %d %s", w.Code, w.Body)
		}
	}
	if o.hits.Load() != 1 {
		t.Fatalf("origin asked %d times", o.hits.Load())
	}
}

func TestFetchFailureIsRemembered(t *testing.T) {
	anyAddr(t)
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	o := newOrigin(t, []byte("gone"))
	o.status = 404
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, key := srcPath(src)
	for range 2 {
		if w := ask(s, path, src, tok); w.Code != 502 || detail(w) != "fetch-failed: the origin answered 404" {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
	if o.hits.Load() != 1 || m.has(key) {
		t.Fatalf("origin asked %d times; stored: %v", o.hits.Load(), m.has(key))
	}
	o.status = 200
	s.now = func() time.Time { return now.Add(failTTL) }
	if w := ask(s, path, src, tok); w.Code != 302 || o.hits.Load() != 2 {
		t.Fatalf("after failTTL: %d, origin asked %d times", w.Code, o.hits.Load())
	}
}

func TestFetchTooLarge(t *testing.T) {
	anyAddr(t)
	for _, chunk := range []bool{false, true} {
		s, tok, _ := setup(t)
		m := newMem()
		s.stores["s3"] = m
		o := newOrigin(t, make([]byte, 1001)) // the binding's max_size is 1000
		o.chunk = chunk
		src := o.URL + "/dl/pkg-1.0.tar.gz"
		path, _ := srcPath(src)
		if w := ask(s, path, src, tok); w.Code != 502 || !strings.Contains(detail(w), "max_size") {
			t.Fatalf("chunked %v: %d %s", chunk, w.Code, w.Body)
		}
		if len(m.objs) != 0 {
			t.Fatalf("chunked %v: objects left: %d", chunk, len(m.objs))
		}
	}
}

func TestFetchOnlyFromPublicAddresses(t *testing.T) {
	s, tok, _ := setup(t)
	s.stores["s3"] = newMem()
	o := newOrigin(t, []byte("x"))
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, _ := srcPath(src)
	notPublic := "fetch-failed: " + string(errNotPublic)
	if w := ask(s, path, src, tok); w.Code != 502 || detail(w) != notPublic {
		t.Fatalf("loopback: %d %s", w.Code, w.Body)
	}
	byName := strings.Replace(src, "127.0.0.1", "localhost", 1)
	path, _ = srcPath(byName)
	if w := ask(s, path, byName, tok); w.Code != 502 || detail(w) != notPublic {
		t.Fatalf("localhost: %d %s", w.Code, w.Body)
	}
	if o.hits.Load() != 0 {
		t.Fatal("loopback origin reached")
	}
	// A redirect is checked as well: 127.0.0.2 stands in for a private address.
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip(err)
	}
	inner := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect's private target was reached")
	}))
	inner.Listener.Close()
	inner.Listener = l
	inner.Start()
	defer inner.Close()
	outer := httptest.NewServer(http.RedirectHandler(inner.URL+"/x.tar.gz", http.StatusFound))
	defer outer.Close()
	allow(t, func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") })
	src = outer.URL + "/dl/pkg-2.0.tar.gz"
	path, _ = srcPath(src)
	if w := ask(s, path, src, tok); w.Code != 502 || detail(w) != notPublic {
		t.Fatalf("redirect: %d %s", w.Code, w.Body)
	}
}

func TestPublic(t *testing.T) {
	for a, want := range map[string]bool{
		"8.8.8.8": true, "137.138.1.1": true, "2001:4860:4860::8888": true, "::ffff:8.8.8.8": true,
		"10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "127.0.0.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "0.1.2.3": false,
		"224.0.0.1": false, "255.255.255.255": false, "198.18.0.1": false, "240.0.0.1": false,
		"::1": false, "::": false, "fe80::1": false, "fc00::1": false, "fd00::1": false, "ff02::1": false,
		"::ffff:10.0.0.1": false, "::ffff:127.0.0.1": false, "::7f00:1": false, "fec0::1": false,
		"2002:a00:1::1": false, "2001:0:a00:1::1": false, "64:ff9b::a00:1": false,
	} {
		if public(netip.MustParseAddr(a)) != want {
			t.Errorf("public(%s) = %v", a, !want)
		}
	}
}

func TestFetchWaitsForABusyName(t *testing.T) {
	anyAddr(t)
	s, tok, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	o := newOrigin(t, []byte("x"))
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, key := srcPath(src)
	s.uploads.lease(s.place["s3"], key, now) // a client's promote of the same name
	if w := ask(s, path, src, tok); w.Code != 202 {
		t.Fatalf("busy: %d %s", w.Code, w.Body)
	}
	for k := range m.objs {
		t.Errorf("left: %s", k)
	}
	s.uploads.release(s.place["s3"], key)
	if w := ask(s, path, src, tok); w.Code != 302 || o.hits.Load() != 2 {
		t.Fatalf("after: %d, origin asked %d times", w.Code, o.hits.Load())
	}
}

func TestFetchFirstWriterWins(t *testing.T) {
	anyAddr(t)
	defer func(d time.Duration) { fetchWait = d }(fetchWait)
	fetchWait = 50 * time.Millisecond
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	o := newOrigin(t, []byte("fetched"))
	o.gate = make(chan struct{})
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, key := srcPath(src)
	if w := ask(s, path, src, tok); w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	m.upload(key, []byte("uploaded meanwhile"))
	close(o.gate)
	for i := 0; ask(s, path, src, tok).Code != 302; i++ {
		if i > 100 {
			t.Fatal("never served")
		}
	}
	settled(t, s)
	if string(m.objs[key]) != "uploaded meanwhile" {
		t.Fatalf("the earlier object replaced: %q", m.objs[key])
	}
	for k := range m.objs {
		if strings.HasPrefix(k, stagingPrefix) {
			t.Errorf("staging left: %s", k)
		}
	}
}

func TestALargeFetchIsPromotedInParts(t *testing.T) {
	anyAddr(t)
	defer func(c int64) { maxCopy = c }(maxCopy)
	data := []byte(strings.Repeat("large ", 100))
	for _, c := range []struct {
		maxCopy   int64
		putParted bool // the staged object's ETag is not its MD5
	}{{10, false}, {10, true}, {1 << 20, true}} {
		maxCopy = c.maxCopy
		s, tok, _ := setup(t)
		m := newMem()
		m.putParted = c.putParted
		s.stores["s3"] = m
		o := newOrigin(t, data)
		src := o.URL + "/dl/pkg-1.0.tar.gz"
		path, key := srcPath(src)
		if w := ask(s, path, src, tok); w.Code != 302 || m.parted[key] != (c.maxCopy == 10) || string(m.objs[key]) != string(data) {
			t.Fatalf("%+v: %d %s parted %v", c, w.Code, w.Body, m.parted[key])
		}
	}
}

func TestFetchAllowed(t *testing.T) {
	pub := netip.MustParseAddr("137.138.1.1")
	if !fetchAllowed(pub, nil) || fetchAllowed(pub, []netip.Prefix{netip.MustParsePrefix("137.138.0.0/16")}) {
		t.Error("fetch_deny not applied")
	}
	if !own(netip.MustParseAddr("127.0.0.1")) || own(pub) {
		t.Error("own addresses not recognised")
	}
	defer func(f func() ([]net.Addr, error)) { interfaceAddrs = f }(interfaceAddrs)
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("137.138.1.1"), Mask: net.CIDRMask(32, 32)}}, nil
	}
	if fetchAllowed(pub, nil) {
		t.Error("the host's own public address allowed")
	}
	if fetchAllowed(netip.MustParseAddr("127.0.0.1"), nil) {
		t.Error("loopback allowed")
	}
	c := &Config{Issuer: "i", Audience: "a", FetchDeny: []string{"137.138.0.0/16", "2001:1458::/32"},
		Keys:     map[string]KeyConfig{"k": {X: strings.Repeat("A", 43), Signer: "user"}},
		Volumes:  map[string]VolumeConf{"v": {Endpoint: "https://s3.example.org", Bucket: "bucket", Region: "r"}},
		Bindings: []Binding{{Prefix: "/a", Volume: "v", Public: true}}}
	if _, err := New(c); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"137.138.1.1", "::ffff:137.138.0.0/112"} {
		c.FetchDeny = []string{bad}
		if _, err := New(c); err == nil {
			t.Errorf("fetch_deny %s accepted", bad)
		}
	}
}

// cutOrigin answers 200 with raw headers and body promising more than it sends,
// then hangs up.
func cutOrigin(t *testing.T, raw string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, buf, _ := w.(http.Hijacker).Hijack()
		buf.WriteString("HTTP/1.1 200 OK\r\n" + raw)
		buf.Flush()
		c.Close()
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/dl/pkg-1.0.tar.gz"
}

func TestFetchCutOffIsNotStored(t *testing.T) {
	anyAddr(t)
	for _, raw := range []string{
		"Transfer-Encoding: chunked\r\n\r\n10\r\nabcdef",
		"Content-Length: 100\r\n\r\nabcdef",
	} {
		s, tok, _ := setup(t)
		m := newMem()
		s.stores["s3"] = m
		src := cutOrigin(t, raw)
		path, _ := srcPath(src)
		if w := ask(s, path, src, tok); w.Code != 502 || detail(w) != "fetch-failed: "+string(errCut) {
			t.Fatalf("%q: %d %s", raw, w.Code, w.Body)
		}
		if len(m.objs) != 0 {
			t.Fatalf("%q: stored %d objects", raw, len(m.objs))
		}
	}
}

func TestFetchStalls(t *testing.T) {
	anyAddr(t)
	defer func(d time.Duration) { fetchStall = d }(fetchStall)
	fetchStall = 100 * time.Millisecond
	s, tok, _ := setup(t)
	m := newMem()
	s.stores["s3"] = m
	o := newOrigin(t, []byte("late"))
	o.gate = make(chan struct{}) // headers never come
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, _ := srcPath(src)
	if w := ask(s, path, src, tok); w.Code != 502 {
		t.Fatalf("no headers: %d %s", w.Code, w.Body)
	}
	// bytes keep coming, but fewer than stallBytes in a window
	stop := make(chan struct{})
	defer close(stop)
	trickle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			select {
			case <-stop:
				return
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Millisecond):
				w.Write([]byte("x"))
				w.(http.Flusher).Flush()
			}
		}
	}))
	defer trickle.Close()
	src = trickle.URL + "/dl/pkg-2.0.tar.gz"
	path, _ = srcPath(src)
	if w := ask(s, path, src, tok); w.Code != 502 || detail(w) != "fetch-failed: "+string(errCut) {
		t.Fatalf("trickle: %d %s", w.Code, w.Body)
	}
	if len(m.objs) != 0 {
		t.Fatalf("stored %d objects", len(m.objs))
	}
}

func TestFetchLimits(t *testing.T) {
	anyAddr(t)
	defer func(d time.Duration) { fetchWait = d }(fetchWait)
	fetchWait = 10 * time.Millisecond
	s, tok, now := setup(t)
	s.stores["s3"] = newMem()
	o := newOrigin(t, []byte("x"))
	o.gate = make(chan struct{})
	for i := range maxFetchPerSubject + 1 {
		src := fmt.Sprintf("%s/dl/pkg-%d.tar.gz", o.URL, i)
		path, _ := srcPath(src)
		w := ask(s, path, src, tok)
		if want := map[bool]int{true: 503, false: 202}[i == maxFetchPerSubject]; w.Code != want || w.Header().Get("Retry-After") == "" {
			t.Fatalf("fetch %d: %d %v", i, w.Code, w.Header())
		}
	}
	close(o.gate)
	settled(t, s)
	o.gate = nil
	// failures take no room from new fetches, and stop being remembered when many
	for i := range maxFailed {
		s.fetches.m[fmt.Sprint(i)] = &fetchJob{until: now.Add(time.Hour)}
	}
	j, _ := s.fetches.join("one more", "x", now)
	s.fetches.finish("one more", j, errCut, now)
	if len(s.fetches.m) != maxFailed {
		t.Fatalf("%d failures remembered", len(s.fetches.m))
	}
	src := o.URL + "/dl/pkg-new.tar.gz"
	path, _ := srcPath(src)
	if w := ask(s, path, src, tok); w.Code != 302 {
		t.Fatalf("with the failures: %d %s", w.Code, w.Body)
	}
}

func TestFetchHead(t *testing.T) {
	anyAddr(t)
	s, tok, _ := setup(t)
	s.stores["s3"] = newMem()
	o := newOrigin(t, []byte("x"))
	src := o.URL + "/dl/pkg-1.0.tar.gz"
	path, _ := srcPath(src)
	w := do(s, "HEAD", path+"?url="+url.QueryEscape(src), map[string]string{"Authorization": "Bearer " + tok})
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "m=HEAD") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}
