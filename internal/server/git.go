// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bitsorg/bits-store/internal/token"
)

// A git binding (README): partial mirrors of upstream repositories under -data's
// git/<key_prefix>, served by git http-backend (protocol v2) to partial clones. Refs
// are fetched first, commits and trees: a tag a client names that the store lacks at
// once, the rest every refsTTL; files as clients name them (a checkout). Tags held
// never move.
const (
	refsTTL    = time.Minute      // refs a client does not name are asked upstream again after this
	gitWait    = 15 * time.Minute // a request waits this long for the repository's fetch
	gitRunTime = time.Hour        // one git command upstream, at most
	maxGitBody = 16 << 20         // a client's request (its haves and wants)
)

var (
	gitScheme  = "https" // tests: http
	gitBackend = ""      // git-http-backend, found once
	gitBinary  = "git"
)

// gitShared is the git bindings' state a reload keeps: where repositories live,
// and when each was last refreshed.
type gitShared struct {
	root      string // -data/git; empty: no git bindings served
	mu        sync.Mutex
	refreshed map[string]time.Time
}

// gitProxy is the proxy git's own fetches go through, so that they reach only the
// addresses the fetch policy allows (the policy of the server that last fetched).
var gitProxy struct {
	once   sync.Once
	url    string
	err    error
	policy atomic.Pointer[fetchPolicy]
}

func startGitProxy(p *fetchPolicy) error {
	gitProxy.policy.Store(p)
	gitProxy.once.Do(func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			gitProxy.err = err
			return
		}
		gitProxy.url = "http://" + ln.Addr().String()
		go http.Serve(ln, http.HandlerFunc(serveGitProxy))
	})
	return gitProxy.err
}

// serveGitProxy tunnels CONNECT (https upstreams) and passes absolute-form requests
// (http: tests), each connection made by the policy's dialer.
func serveGitProxy(w http.ResponseWriter, r *http.Request) {
	p := gitProxy.policy.Load()
	if r.Method == http.MethodConnect {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		up, err := p.dial(ctx, "tcp", r.Host)
		cancel()
		if err != nil {
			log.Printf("git fetch to %s: %v", r.Host, err)
			http.Error(w, "not allowed", http.StatusBadGateway)
			return
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			up.Close()
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { io.Copy(up, conn); up.Close() }()
		io.Copy(conn, up)
		conn.Close()
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "a proxy", http.StatusBadRequest)
		return
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out.Header = r.Header.Clone()
	out.Header.Del("Proxy-Connection")
	out.ContentLength = r.ContentLength
	resp, err := p.client().Transport.RoundTrip(out)
	if err != nil {
		log.Printf("git fetch from %s: %v", r.URL.Host, err)
		http.Error(w, "not allowed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// UseGit keeps git bindings' repositories in dir (-data's), made if need be.
func (r *Reloader) UseGit(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	r.cur.Load().git.root = dir
	return nil
}

// serveGit answers git's smart HTTP for a git binding: GET info/refs (protocol v2
// only; older clients are sent upstream) and POST git-upload-pack.
func (s *Server) serveGit(w http.ResponseWriter, r *http.Request, b *Binding, key, p string, t *token.Token, now time.Time) int {
	repo := b.unprefixed(key)
	upstream := gitScheme + "://" + repo
	info := strings.HasSuffix(p, "/info/refs")
	if s.git.root == "" {
		s.errorf("git_no_data", b.Prefix, "git binding %q: no -data to keep repositories in", b.Prefix)
		return fail(w, http.StatusServiceUnavailable)
	}
	if info && r.URL.Query().Get("service") != "git-upload-pack" {
		return fail(w, http.StatusForbidden) // a mirror: never pushed to
	}
	if info && !strings.Contains(r.Header.Get("Git-Protocol"), "version=2") {
		w.Header().Set("Location", upstream+"/info/refs?service=git-upload-pack") // names no refs: upstream
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusFound)
		return http.StatusFound
	}
	if !info && r.Method != http.MethodPost {
		return fail(w, http.StatusMethodNotAllowed)
	}
	root := filepath.Join(s.git.root, filepath.FromSlash(b.KeyPrefix))
	dir := filepath.Join(root, filepath.FromSlash(repo)+".git")
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(gitWait + 2*time.Hour))
	var raw []byte
	if !info {
		var err error
		if raw, err = io.ReadAll(io.LimitReader(r.Body, maxGitBody+1)); err != nil || len(raw) > maxGitBody {
			return fail(w, http.StatusRequestEntityTooLarge)
		}
		req, err := gitRequest(raw, r.Header.Get("Content-Encoding"))
		if err != nil {
			return failMsg(w, http.StatusBadRequest, err.Error())
		}
		if req.command == "fetch" && !req.filter {
			return failMsg(w, http.StatusBadRequest, "a partial mirror: clone with --filter=tree:0 or blob:none")
		}
		if err := s.gitPrepare(r.Context(), dir, upstream, req, t, now); err != nil {
			s.errorf("git_failed", repo, "git %s: %v", repo, err)
			return fail(w, http.StatusBadGateway)
		}
	} else if !gitHeld(dir) {
		if err := s.gitLocked(r.Context(), dir, upstream, t, now, func(ctx context.Context) error {
			return gitInit(ctx, dir, upstream)
		}); err != nil {
			s.errorf("git_failed", repo, "git %s: %v", repo, err)
			return fail(w, http.StatusBadGateway)
		}
	}
	return s.gitBackend(w, r, root, repo, raw)
}

var gitOID = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// gitReq is what a protocol v2 request asks: its command, ref prefixes, wants.
type gitReq struct {
	command  string
	prefixes []string
	wants    []string
	filter   bool // a partial clone's: what a partial mirror can serve
}

// gitRequest reads a protocol v2 request's pkt-lines (gzip as the client sent it).
func gitRequest(raw []byte, encoding string) (gitReq, error) {
	var rd io.Reader = bytes.NewReader(raw)
	if encoding == "gzip" {
		z, err := gzip.NewReader(rd)
		if err != nil {
			return gitReq{}, err
		}
		rd = io.LimitReader(z, maxGitBody)
	}
	br, q := bufio.NewReader(rd), gitReq{}
	for {
		var head [4]byte
		if _, err := io.ReadFull(br, head[:]); err == io.EOF {
			return q, nil
		} else if err != nil {
			return q, errors.New("a truncated pkt-line")
		}
		n, err := strconv.ParseUint(string(head[:]), 16, 16)
		if err != nil {
			return q, errors.New("not pkt-lines")
		}
		if n < 4 { // flush, delimiter, response end
			continue
		}
		line := make([]byte, n-4)
		if _, err := io.ReadFull(br, line); err != nil {
			return q, errors.New("a truncated pkt-line")
		}
		l := strings.TrimSuffix(string(line), "\n")
		switch {
		case strings.HasPrefix(l, "command="):
			q.command = strings.TrimPrefix(l, "command=")
		case strings.HasPrefix(l, "ref-prefix "):
			q.prefixes = append(q.prefixes, strings.TrimPrefix(l, "ref-prefix "))
		case strings.HasPrefix(l, "want "):
			w := strings.TrimPrefix(l, "want ")
			if !gitOID.MatchString(w) { // given to git as an argument: never an option
				return q, errors.New("a want that is not an object id")
			}
			q.wants = append(q.wants, w)
		case strings.HasPrefix(l, "filter "):
			q.filter = true
		}
	}
}

// gitPrepare fetches what a request needs before git answers it from the mirror:
// for ls-refs, the refs (a named tag the store lacks at once, the rest every
// refsTTL); for fetch, the files of the commits wanted, and anything else missing.
func (s *Server) gitPrepare(ctx context.Context, dir, upstream string, q gitReq, t *token.Token, now time.Time) error {
	switch q.command {
	case "ls-refs":
		if !s.gitStale(dir, now) && !missingTag(ctx, dir, q.prefixes) {
			return nil
		}
		err := s.gitLocked(ctx, dir, upstream, t, now, func(ctx context.Context) error {
			if err := gitInit(ctx, dir, upstream); err != nil {
				return err
			}
			if !s.gitStale(dir, now) && !missingTag(ctx, dir, q.prefixes) {
				return nil // done by the request waited for
			}
			if err := s.gitRefresh(ctx, dir, upstream); err != nil {
				return err
			}
			s.git.mu.Lock()
			s.git.refreshed[dir] = now
			s.git.mu.Unlock()
			return nil
		})
		if err != nil && gitHeld(dir) && !missingTag(ctx, dir, q.prefixes) {
			s.warnf("git_upstream_down", upstream, "git %s: refs not refreshed, served as held: %v", dir, err) // upstream down
			return nil
		}
		return err
	case "fetch":
		if len(gitAbsent(gitTypes(ctx, dir, q.wants))) > 0 {
			if err := s.gitLocked(ctx, dir, upstream, t, now, func(ctx context.Context) error {
				if err := gitInit(ctx, dir, upstream); err != nil {
					return err
				}
				return gitFill(ctx, dir, q.wants)
			}); err != nil {
				return err
			}
		}
		return gitKeep(ctx, dir, q.wants)
	}
	return nil
}

// gitLocked runs work as the repository's one fetch, under the fetch table's rules
// (room, budgets for untrusted hosts); a request finding one running waits for it.
func (s *Server) gitLocked(ctx context.Context, dir, upstream string, t *token.Token, now time.Time, work func(context.Context) error) error {
	if err := startGitProxy(s.policy); err != nil {
		return err
	}
	host := strings.ToLower(urlHost(upstream))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	var budget *fetchPolicy // a new repository of an untrusted host counts, not its refreshes
	if !s.policy.isTrusted(host) && !gitHeld(dir) {
		budget = s.policy
	}
	sub := "anonymous"
	if t != nil {
		sub = t.Sub
	}
	k := "git\x00" + dir
	end := time.Now().Add(gitWait)
	for {
		job, fresh, err := s.fetches.join(k, sub, domainOf(host), budget, s.now())
		switch {
		case errors.Is(err, errFull) && time.Now().Before(end):
			time.Sleep(roomPoll)
			continue
		case err != nil:
			s.meters.refuse("git", map[bool]string{true: "throttled", false: "full"}[errors.Is(err, errThrottled)])
			return err
		case !fresh:
			select {
			case <-job.done: // another's fetch: then ours, if still needed
			case <-ctx.Done():
				return ctx.Err()
			}
			if job.err != nil {
				return job.err
			}
			continue
		}
		wctx, cancel := context.WithTimeout(context.Background(), gitRunTime) // not the client's
		err = work(wctx)
		cancel()
		s.meters.fill("git", 0, err)
		s.fetches.finish(k, job, err, s.now())
		return err
	}
}

func (s *Server) gitStale(dir string, now time.Time) bool {
	s.git.mu.Lock()
	defer s.git.mu.Unlock()
	at, ok := s.git.refreshed[dir]
	return !ok || now.Sub(at) >= refsTTL || now.Before(at)
}

// missingTag: a ref prefix naming one tag the repository does not hold.
func missingTag(ctx context.Context, dir string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(p, "refs/tags/") && !strings.HasSuffix(p, "/") {
			if _, err := gitOut(ctx, dir, nil, "rev-parse", "-q", "--verify", p); err != nil {
				return true
			}
		}
	}
	return false
}

func gitHeld(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "HEAD"))
	return err == nil
}

// gitInit makes the repository, a partial mirror of upstream, unless it exists.
func gitInit(ctx context.Context, dir, upstream string) error {
	if gitHeld(dir) {
		return nil
	}
	tmp := dir + ".new"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if _, err := gitOut(ctx, "", nil, "init", "-q", "--bare", "--template=", tmp); err != nil {
		return err
	}
	for _, kv := range [][2]string{{"remote.origin.url", upstream}, {"remote.origin.promisor", "true"},
		{"extensions.partialClone", "origin"}, {"uploadpack.allowFilter", "true"},
		{"uploadpack.allowAnySHA1InWant", "true"}, {"gc.auto", "0"}, {"maintenance.auto", "false"}} {
		if _, err := gitOut(ctx, tmp, nil, "config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	if _, err := gitOut(ctx, tmp, nil, "ls-remote", "origin", "HEAD"); err != nil {
		os.RemoveAll(tmp) // no such repository upstream: nothing kept
		return err
	}
	return os.Rename(tmp, dir)
}

// gitRefresh fetches upstream's refs, commits and trees without files (git's server
// walks the trees of what it sends, filtered or not): branches as they are now, tags
// never moved (git refuses that, logged), HEAD as upstream's default branch.
func (s *Server) gitRefresh(ctx context.Context, dir, upstream string) error {
	out, err := gitOut(ctx, dir, nil, "fetch", "--filter=blob:none", "--no-tags", "--no-write-fetch-head",
		"origin", "+refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*")
	if err != nil {
		if !strings.Contains(out, "would clobber existing tag") {
			return err
		}
		for _, l := range strings.Split(out, "\n") {
			if _, said := gitMovedSaid.LoadOrStore(dir+"\x00"+l, true); !said && strings.Contains(l, "would clobber existing tag") {
				s.warnf("tag_moved", upstream, "git %s: a tag moved upstream, kept as it was: %s", dir, strings.TrimSpace(l))
			}
		}
	}
	if out, err := gitOut(ctx, dir, nil, "ls-remote", "--symref", "origin", "HEAD"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) == 3 && f[0] == "ref:" && f[2] == "HEAD" {
				gitOut(ctx, dir, nil, "symbolic-ref", "HEAD", f[1])
			}
		}
	}
	return nil
}

var gitMovedSaid sync.Map // each moved tag logged once

// gitTypes is the type of each object named ("missing" for one not held).
func gitTypes(ctx context.Context, dir string, oids []string) map[string]string {
	types := make(map[string]string, len(oids))
	for _, o := range oids {
		types[o] = "missing"
	}
	out, _ := gitOut(ctx, dir, strings.NewReader(strings.Join(oids, "\n")+"\n"), "cat-file", "--batch-check")
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && types[f[0]] != "" {
			types[f[0]] = f[1]
		}
	}
	return types
}

func gitAbsent(types map[string]string) []string {
	var absent []string
	for o, t := range types {
		if t == "missing" {
			absent = append(absent, o)
		}
	}
	return absent
}

// gitFill fetches the wanted objects not held, as git's lazy fetch asks them: no
// files beyond those named, and no haves (GitHub sends no file a have reaches).
// A client's checkout names its files, so the store keeps what builds check out.
func gitFill(ctx context.Context, dir string, wants []string) error {
	absent := gitAbsent(gitTypes(ctx, dir, wants))
	if len(absent) == 0 {
		return nil // fetched by the request waited for
	}
	in := strings.NewReader(strings.Join(absent, "\n") + "\n")
	if _, err := gitOut(ctx, dir, in, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--filter=blob:none",
		"--no-tags", "--no-write-fetch-head", "--stdin", "origin"); err != nil {
		return err
	}
	if absent = gitAbsent(gitTypes(ctx, dir, absent)); len(absent) > 0 {
		return fmt.Errorf("%d objects not sent by upstream", len(absent))
	}
	return nil
}

// gitKeep holds each tree wanted, the root of a client's checkout, under
// refs/bits/<oid>: what a build used stays when upstream moves or deletes it.
func gitKeep(ctx context.Context, dir string, wants []string) error {
	for o, t := range gitTypes(ctx, dir, wants) {
		if t == "tree" { // one already kept is refused: fine
			gitOut(ctx, dir, strings.NewReader("create refs/bits/"+o+" "+o+"\n"), "update-ref", "--stdin")
		}
	}
	return nil
}

// gitOut runs git in dir with the mirror's settings; its fetches go through the
// policy's proxy. The output (both streams) is returned, and is the error's text.
func gitOut(ctx context.Context, dir string, stdin io.Reader, args ...string) (string, error) {
	c := []string{"-c", "protocol.allow=never", "-c", "protocol." + gitScheme + ".allow=always",
		"-c", "http.followRedirects=true", "-c", "credential.helper=", "-c", "core.askPass=true"}
	if gitProxy.url != "" {
		c = append(c, "-c", "http.proxy="+gitProxy.url)
	}
	if dir != "" {
		c = append(c, "-C", dir)
	}
	cmd := exec.CommandContext(ctx, gitBinary, append(c, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1"}
	cmd.Stdin = stdin
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(out.String()))
	}
	return out.String(), err
}

// gitBackend has git http-backend answer from the mirror, the request body as sent.
func (s *Server) gitBackend(w http.ResponseWriter, r *http.Request, root, repo string, raw []byte) int {
	if gitBackend == "" {
		out, err := exec.Command(gitBinary, "--exec-path").Output()
		if err != nil {
			s.errorf("git_missing", "", "git --exec-path: %v", err)
			return fail(w, http.StatusServiceUnavailable)
		}
		gitBackend = filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	}
	op := "info/refs"
	if raw != nil {
		op = "git-upload-pack"
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/" + repo + ".git/" + op
	r2.URL.RawPath = ""
	r2.Body = io.NopCloser(bytes.NewReader(raw))
	r2.ContentLength = int64(len(raw))
	h := &cgi.Handler{Path: gitBackend, Root: "", Env: []string{"GIT_PROJECT_ROOT=" + root,
		"GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"HOME=/nonexistent", "GIT_NO_LAZY_FETCH=1"}, InheritEnv: []string{"PATH"},
		Stderr: logWriter{s, repo}}
	h.Logger = log.New(logWriter{s, repo}, "", 0) // its own errors ("CGI error"): problems too
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	h.ServeHTTP(sw, r2)
	return sw.code
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

// logWriter makes what git http-backend (or its CGI handler) writes a problem.
type logWriter struct {
	s    *Server
	repo string
}

func (w logWriter) Write(b []byte) (int, error) {
	w.s.errorf("git_backend", w.repo, "git http-backend: %s", strings.TrimSpace(string(b)))
	return len(b), nil
}
