// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SignerConf is a security-proxy sign route, found through its agent socket (as
// bits-console's signproxy): the socket names the route's port and gate token.
type SignerConf struct {
	AgentSocket string `json:"agent_socket"` // /run/store-token-signer/agent.sock
	Route       string `json:"route"`        // the route's name
	Host        string `json:"host"`         // where its port is: store-token-signer
	Prefix      string `json:"prefix"`       // its path: /sign/restricted
}

const (
	signerCache = 5 * time.Minute  // the proxy rotates its gate token daily, its port on restart
	signerTime  = 15 * time.Second // the most one signature may take, retry included
	// The domain of what is signed: never a manifest's bytes.
	restrictedDomain = "bits-restricted-build v1\n"
)

var (
	signerRoute = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	signerHost  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	signerKeyID = regexp.MustCompile(`^[0-9a-f]{16}`)
)

// proxySigner signs bytes with the route's Ed25519 key, which never leaves the proxy.
type proxySigner struct {
	conf   SignerConf
	client *http.Client
	now    func() time.Time

	mu         sync.Mutex // guards the endpoint kept; never held over I/O
	url, token string
	until      time.Time
}

func newSigner(c SignerConf) (*proxySigner, error) {
	if c == (SignerConf{}) {
		return nil, nil
	}
	if !strings.HasPrefix(c.AgentSocket, "/") || !signerRoute.MatchString(c.Route) ||
		!signerHost.MatchString(c.Host) || !strings.HasPrefix(c.Prefix, "/") {
		return nil, errors.New("restricted_signer: agent_socket (absolute), route, host (a name) and prefix (/...)")
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true} // the gate token to the route only
	return &proxySigner{conf: c, now: time.Now, client: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// endpoint is the route's URL and gate token: kept for signerCache, else (or
// *fresh*) asked of the agent socket.
func (g *proxySigner) endpoint(ctx context.Context, fresh bool) (string, string, error) {
	g.mu.Lock()
	url, token, ok := g.url, g.token, g.url != "" && g.now().Before(g.until)
	g.mu.Unlock()
	if ok && !fresh {
		return url, token, nil
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", g.conf.AgentSocket)
	if err != nil {
		return "", "", fmt.Errorf("sign proxy agent socket: %v", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write([]byte(g.conf.Route + "\n")); err != nil {
		return "", "", fmt.Errorf("sign proxy agent socket: %v", err)
	}
	var a struct {
		Port  int    `json:"port"`
		Token string `json:"token"`
		Error string `json:"error"`
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return "", "", fmt.Errorf("sign proxy agent socket: %v", err)
	}
	if json.Unmarshal(line, &a) != nil || a.Port <= 0 || a.Port > 65535 || a.Token == "" {
		return "", "", fmt.Errorf("sign proxy agent socket: no token for route %q (%s)", g.conf.Route, cmpOr(a.Error, "no answer"))
	}
	url = fmt.Sprintf("http://%s%s", net.JoinHostPort(g.conf.Host, fmt.Sprint(a.Port)), g.conf.Prefix)
	g.mu.Lock()
	g.url, g.token, g.until = url, a.Token, g.now().Add(signerCache)
	g.mu.Unlock()
	return url, a.Token, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sign returns the key id (16 hex, as bits' key_id) and the signature of data,
// within signerTime. A failure asks the agent socket again, once, and retries if
// the endpoint changed (a new port or a rotated gate token).
func (g *proxySigner) sign(ctx context.Context, data []byte) (string, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, signerTime)
	defer cancel()
	url, token, err := g.endpoint(ctx, false)
	if err != nil {
		return "", nil, err
	}
	kid, sig, err := g.post(ctx, url, token, data)
	if err == nil {
		return kid, sig, nil
	}
	url2, token2, ferr := g.endpoint(ctx, true)
	if ferr != nil || url2 == url && token2 == token {
		return "", nil, err
	}
	return g.post(ctx, url2, token2, data)
}

func (g *proxySigner) post(ctx context.Context, url, token string, data []byte) (string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("sign proxy: %v", err)
	}
	defer resp.Body.Close()
	var a struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("sign proxy: HTTP %d", resp.StatusCode)
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&a) != nil || !signerKeyID.MatchString(strings.ToLower(a.KeyID)) {
		return "", nil, errors.New("sign proxy: an answer without a key id and signature")
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", nil, errors.New("sign proxy: not an Ed25519 signature")
	}
	return strings.ToLower(a.KeyID)[:16], sig, nil
}

// restrictedStatement is what a restricted build's signature covers: the domain
// line, then canonical JSON (keys sorted, no spaces, as Python's sort_keys); the
// same bytes as Python's because the path rules keep every field ASCII.
func restrictedStatement(arch, hash, group, name, sha256 string) []byte {
	var b bytes.Buffer
	b.WriteString(restrictedDomain)
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(struct {
		Arch   string `json:"arch"`
		Group  string `json:"group"`
		Hash   string `json:"hash"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}{arch, group, hash, name, sha256})
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
