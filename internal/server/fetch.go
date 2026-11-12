// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/format"
	"github.com/bitsorg/bits-store/internal/token"
)

// Fetches for a Mirror binding (sources): README. A miss is fetched once, where
// the policy allows (policy.go), into staging, then promoted.
const (
	fetchPart          = 16 << 20 // streamed to the volume in parts of at least this
	maxFetch           = 1 << 40  // a binding's max_size at most
	maxFetching        = 16       // fetches at once
	maxFetchPerSubject = 4
	maxFailed          = 10000   // remembered failures
	stallBytes         = 1 << 20 // a fetch must bring this much per fetchStall
	fetchTimeout       = 12 * time.Hour
	failTTL            = 10 * time.Minute
)

var (
	fetchWait  = 20 * time.Second // a request waits this long for its fetch
	fetchStall = 5 * time.Minute
)

// fetchError is a failure the asker may be told of; other errors are logged only.
type fetchError string

func (e fetchError) Error() string { return string(e) }

var (
	errBusy      = errors.New("the name is being promoted")
	errCut       = fetchError("the origin's answer was cut off or stalled")
	errThrottled = errors.New("the day's budget for the domain or subject is spent")
	errFull      = errors.New("too many fetches running")
)

type fetchJob struct {
	sub   string
	done  chan struct{}
	err   error     // set before done closes
	until time.Time // a failure is remembered until then
}

// fetchTable holds running fetches, recent failures and the day's counts of
// untrusted fetches. A reload shares it, like the upload table.
type fetchTable struct {
	mu              sync.Mutex
	m               map[string]*fetchJob
	day             string
	bySub, byDomain map[string]int
}

// join returns the key's running or failed fetch, or a new one (fresh true):
// errFull when there is no room (failures take none), errThrottled when budget,
// the policy of an untrusted domain, is spent for the day.
func (ft *fetchTable) join(k, sub, domain string, budget *fetchPolicy, now time.Time) (job *fetchJob, fresh bool, err error) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if ft.m == nil {
		ft.m = map[string]*fetchJob{}
	}
	if j := ft.m[k]; j != nil && (j.until.IsZero() || now.Before(j.until)) {
		return j, false, nil
	}
	running, mine := 0, 0
	for jk, j := range ft.m {
		switch {
		case !j.until.IsZero() && !now.Before(j.until):
			delete(ft.m, jk)
		case j.until.IsZero():
			running++
			if j.sub == sub {
				mine++
			}
		}
	}
	if running >= maxFetching || mine >= maxFetchPerSubject {
		return nil, false, errFull
	}
	if budget != nil {
		if day := now.UTC().Format(time.DateOnly); day != ft.day {
			ft.day, ft.bySub, ft.byDomain = day, map[string]int{}, map[string]int{}
		}
		if ft.bySub[sub] >= budget.perSubject || ft.byDomain[domain] >= budget.perDomain {
			return nil, false, errThrottled
		}
		ft.bySub[sub]++
		ft.byDomain[domain]++
	}
	j := &fetchJob{sub: sub, done: make(chan struct{})}
	ft.m[k] = j
	return j, true, nil
}

// finish records a fetch's outcome: a failure is remembered for failTTL while
// there is room, except errBusy, which the next ask retries.
func (ft *fetchTable) finish(k string, j *fetchJob, err error, now time.Time) {
	ft.mu.Lock()
	j.err = err
	failed := 0
	for _, o := range ft.m {
		if !o.until.IsZero() {
			failed++
		}
	}
	if err == nil || errors.Is(err, errBusy) || failed >= maxFailed {
		delete(ft.m, k)
	} else {
		j.until = now.Add(failTTL)
	}
	ft.mu.Unlock()
	close(j.done)
}

func (ft *fetchTable) forgetFailures() {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	for k, j := range ft.m {
		if !j.until.IsZero() {
			delete(ft.m, k)
		}
	}
}

func failDetail(w http.ResponseWriter, code int, msg, detail string) int {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "detail": detail})
	return code
}

func (s *Server) fetchRead(w http.ResponseWriter, r *http.Request, rawQuery string, b *Binding, key string, t *token.Token, now time.Time) int {
	q, err := url.ParseQuery(rawQuery)
	if err != nil || len(q) != 1 || len(q["url"]) != 1 {
		return failMsg(w, http.StatusBadRequest, "bad-request")
	}
	src := q.Get("url")
	item := format.Item{Key: strings.TrimPrefix(key, b.KeyPrefix+"/")}
	if b.KeyPrefix == "" {
		item.Key = key
	}
	if err := b.mirror.Origin(item, src); err != nil {
		return failDetail(w, http.StatusBadRequest, "bad-url", err.Error())
	}
	if _, ok, err := s.stores[b.Volume].Stat(r.Context(), key); err != nil {
		log.Printf("stat %s: %v", key, err)
		return fail(w, http.StatusBadGateway)
	} else if ok {
		return s.redirect(w, r, b, key, t, now)
	}
	host := strings.ToLower(strings.TrimSuffix(urlHost(src), "."))
	var budget *fetchPolicy
	if !s.policy.isTrusted(host) {
		budget = s.policy
	}
	k := s.place[b.Volume] + "\x00" + key
	who := fmt.Sprintf("sub=%q grp=%q jti=%q", t.Sub, t.Grp, t.Jti)
	job, fresh, err := s.fetches.join(k, t.Sub, domainOf(host), budget, now)
	switch {
	case errors.Is(err, errThrottled):
		log.Printf("fetch %s from %s for %s: throttled", key, src, who)
		midnight := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		w.Header().Set("Retry-After", fmt.Sprint(int(midnight.Sub(now).Seconds())+1))
		return failMsg(w, http.StatusTooManyRequests, "throttled")
	case err != nil:
		w.Header().Set("Retry-After", "30")
		return failMsg(w, http.StatusServiceUnavailable, "full")
	}
	if fresh {
		log.Printf("fetch %s from %s for %s", key, src, who)
		go func() {
			start := time.Now()
			n, err := s.fetch(b.Volume, b.MaxSize, key, src, t.Sub)
			if err != nil {
				log.Printf("fetch %s from %s for %s failed after %d bytes, %s: %v", key, src, who, n, time.Since(start).Round(time.Millisecond), err)
			} else {
				log.Printf("fetched %s from %s for %s: %d bytes in %s", key, src, who, n, time.Since(start).Round(time.Millisecond))
			}
			s.fetches.finish(k, job, err, s.now())
		}()
	}
	select {
	case <-job.done:
	case <-time.After(fetchWait):
	case <-r.Context().Done():
	}
	finished := false
	select {
	case <-job.done:
		finished = true
	default:
	}
	if !finished || errors.Is(job.err, errBusy) {
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "fetching"})
		return http.StatusAccepted
	}
	if job.err != nil {
		detail := "the origin could not be fetched" // the rest is logged only
		var fe fetchError
		if errors.As(job.err, &fe) {
			detail = fe.Error()
		}
		return failDetail(w, http.StatusBadGateway, "fetch-failed", detail)
	}
	return s.redirect(w, r, b, key, t, now)
}

// fetch streams src into staging, computing its checksums, and promotes it to key:
// the bytes read. Another object already at key is a success: the first writer won.
func (s *Server) fetch(volume string, maxSize int64, key, src, sub string) (n int64, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	stall := time.AfterFunc(fetchStall, cancel)
	defer stall.Stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "bits-store")
	resp, err := s.fetchClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fetchError(fmt.Sprintf("the origin answered %d", resp.StatusCode))
	}
	tooLarge := fetchError(fmt.Sprintf("larger than the binding's max_size, %d bytes", maxSize))
	if resp.ContentLength > maxSize {
		return 0, tooLarge
	}
	idb := make([]byte, 16)
	rand.Read(idb)
	id := hex.EncodeToString(idb)
	staging := stagingPrefix + "/" + id
	st := s.stores[volume]
	remove := func() {
		rctx, rcancel := context.WithTimeout(context.Background(), stepTimeout)
		defer rcancel()
		if err := st.Remove(rctx, staging); err != nil {
			log.Printf("remove %s: %v", staging, err)
		}
	}
	body := &fetchBody{r: resp.Body, left: maxSize, stall: stall, sha: sha256.New(), md5: md5.New()}
	part := max(fetchPart, maxSize/9999+1) // S3 takes up to 10000 parts
	err = st.Put(ctx, staging, body, part, map[string]string{"bits-upload": id})
	switch {
	case body.over:
		return body.n, tooLarge // no object: a failed multipart upload is aborted
	case body.cut != nil:
		return body.n, fmt.Errorf("%w: %v", errCut, body.cut)
	case err != nil:
		return body.n, err
	}
	sum := hex.EncodeToString(body.sha.Sum(nil))
	u := &upload{volume: volume, key: key, staging: staging, size: body.n, fetched: true,
		md5Hex: hex.EncodeToString(body.md5.Sum(nil)), sha256: sum,
		meta: map[string]string{"sha256": sum, "source-url": src, "fetched-by": url.PathEscape(sub)}}
	switch code, msg := s.promote(context.Background(), u, id, s.now()); {
	case code == http.StatusCreated || msg == "exists":
		return body.n, nil
	case msg == "busy":
		remove()
		return body.n, errBusy
	default:
		return body.n, fmt.Errorf("promote: %d %s", code, msg) // staging may be kept: the lifecycle rule
	}
}

// fetchBody counts and hashes what it reads, ends at the size limit, keeps the
// stall timer off while enough bytes come, and stops it at the end.
type fetchBody struct {
	r              io.Reader
	n, left, since int64 // since: bytes since the stall timer was reset
	over           bool
	cut            error // the read error, other than the end
	stall          *time.Timer
	sha, md5       hash.Hash
}

func (f *fetchBody) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if int64(n) > f.left {
		f.over = true
		return 0, errors.New("too large")
	}
	f.left -= int64(n)
	f.n += int64(n)
	f.sha.Write(p[:n])
	f.md5.Write(p[:n])
	if f.since += int64(n); f.since >= stallBytes {
		f.since = 0
		f.stall.Reset(fetchStall)
	}
	switch {
	case err == io.EOF:
		f.stall.Stop() // the upload's last part may still take a while
	case err != nil:
		f.cut = err
		err = errCut // never io.ErrUnexpectedEOF: minio-go takes it for the end
	}
	return n, err
}

// urlHost is the host of a URL Origin accepted.
func urlHost(src string) string {
	u, err := url.Parse(src)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
