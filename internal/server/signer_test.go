// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// standIn is a security proxy's sign route and its agent socket, as the proxy
// answers: the socket a port and gate token per route, the route {keyid, sig}.
type standIn struct {
	conf          SignerConf
	pub           ed25519.PublicKey
	token         atomic.Value // the gate token the route takes now
	asked, signed atomic.Int32
	fail          atomic.Bool
}

func newStandIn(t *testing.T) *standIn {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	g := &standIn{pub: pub}
	g.token.Store("gate-1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign/restricted" || r.Header.Get("Authorization") != "Bearer "+g.token.Load().(string) || g.fail.Load() {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		data, _ := io.ReadAll(r.Body)
		g.signed.Add(1)
		sum := sha256.Sum256(pub)
		json.NewEncoder(w).Encode(map[string]string{"keyid": hex.EncodeToString(sum[:]),
			"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))})
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	dir, err := os.MkdirTemp("/tmp", "sg") // a socket path is short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			route, _ := bufio.NewReader(c).ReadString('\n')
			g.asked.Add(1)
			if route == "bits-restricted-sign\n" {
				fmt.Fprintf(c, `{"port": %s, "token": %q}`+"\n", port, g.token.Load().(string))
			} else {
				fmt.Fprintln(c, `{"error": "no such route"}`)
			}
			c.Close()
		}
	}()
	g.conf = SignerConf{AgentSocket: sock, Route: "bits-restricted-sign", Host: "127.0.0.1", Prefix: "/sign/restricted"}
	return g
}

func TestTheSigner(t *testing.T) {
	g := newStandIn(t)
	s, err := newSigner(g.conf)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	data := restrictedStatement("x86_64-el9", "ab", "lhcb", "a-1-1.x86_64-el9.tar.gz", "00")
	kid, sig, err := s.sign(ctx, data)
	sum := sha256.Sum256(g.pub)
	if err != nil || kid != hex.EncodeToString(sum[:8]) || !ed25519.Verify(g.pub, data, sig) {
		t.Fatalf("%q %v", kid, err)
	}
	if _, _, err := s.sign(ctx, data); err != nil || g.asked.Load() != 1 {
		t.Fatalf("the endpoint not kept: asked %d, %v", g.asked.Load(), err)
	}
	g.token.Store("gate-2") // rotated: asked again, once
	if _, _, err := s.sign(ctx, data); err != nil || g.asked.Load() != 2 {
		t.Fatalf("a rotated token: asked %d, %v", g.asked.Load(), err)
	}
	g.fail.Store(true) // refusing, the endpoint unchanged: no retry beyond one ask
	if _, _, err := s.sign(ctx, data); err == nil || g.asked.Load() != 3 {
		t.Fatalf("a refusal: asked %d, %v", g.asked.Load(), err)
	}
	conf := g.conf
	conf.Route = "another"
	other, _ := newSigner(conf)
	if _, _, err := other.sign(ctx, data); err == nil || !strings.Contains(err.Error(), "no token for route") {
		t.Fatalf("an unknown route: %v", err)
	}
	for _, c := range []SignerConf{{Route: "r"}, {AgentSocket: "rel.sock", Route: "r", Host: "h", Prefix: "/p"},
		{AgentSocket: "/a.sock", Route: "r", Host: "h", Prefix: "p"}, {AgentSocket: "/a.sock", Route: "r\nx", Host: "h", Prefix: "/p"},
		{AgentSocket: "/a.sock", Route: "r", Host: "h:1", Prefix: "/p"}} {
		if _, err := newSigner(c); err == nil {
			t.Fatalf("%+v accepted", c)
		}
	}
	if s, err := newSigner(SignerConf{}); s != nil || err != nil {
		t.Fatal("none configured is no signer")
	}
}

// The endpoint is asked again once it is old; a socket that never answers costs
// signerTime at most.
func TestTheSignerInTime(t *testing.T) {
	g := newStandIn(t)
	s, _ := newSigner(g.conf)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	data := []byte("x")
	s.sign(context.Background(), data)
	clock = clock.Add(signerCache)
	if _, _, err := s.sign(context.Background(), data); err != nil || g.asked.Load() != 2 {
		t.Fatalf("an old endpoint kept: asked %d, %v", g.asked.Load(), err)
	}
	dir, _ := os.MkdirTemp("/tmp", "sg")
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { // accepts, never answers
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	hung, _ := newSigner(SignerConf{AgentSocket: filepath.Join(dir, "agent.sock"), Route: "r", Host: "h", Prefix: "/p"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	began := time.Now()
	if _, _, err := hung.sign(ctx, data); err == nil || time.Since(began) > 2*time.Second {
		t.Fatalf("a hung socket: %v after %v", err, time.Since(began))
	}
}

// What is signed is the domain line and canonical JSON, as Python's
// json.dumps(..., sort_keys=True, separators=(",", ":")) writes it.
func TestTheRestrictedStatement(t *testing.T) {
	got := string(restrictedStatement("x86_64-el9", "ab12", "a.b_c-d", "Aa0._~+!@=,:-1.0-1.x86_64-el9.tar.gz", "ff"))
	want := "bits-restricted-build v1\n" + `{"arch":"x86_64-el9","group":"a.b_c-d","hash":"ab12","name":"Aa0._~+!@=,:-1.0-1.x86_64-el9.tar.gz","sha256":"ff"}`
	if got != want {
		t.Fatalf("%q", got)
	}
}
