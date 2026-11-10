// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/token"
)

// Writes (ADR 0004 D): a client never gets a URL for a final key.
//
//	POST <path>?uploads          {"size", "md5" (base64), "sha256" (hex)}
//	                             -> 201 {"id", "url", "method", "headers", "expires", "complete_by"}
//	PUT  <url> with the headers  (straight to the volume, into STAGING/<id>)
//	POST <path>?complete=<id>    -> 201 promoted (also on a retry), 409 the name exists
//	                                or is being promoted, 422 wrong size or MD5
//
// Size and MD5 are checked; the SHA-256 is the uploader's declaration, kept as
// "declared-sha256". First-writer-wins needs one instance: the lease is in memory.
const (
	stagingPrefix = "STAGING"
	maxUpload     = 5 << 30 // one presigned PUT; multipart comes later
	maxPending    = 10000
	maxPerSubject = 100
	completeGrace = time.Hour // after the URL expires, time left to complete
	minTokenLeft  = time.Minute
	copyTimeout   = 10 * time.Minute
)

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

type upload struct {
	volume, key, staging, sub string
	size                      int64
	md5Hex, md5B64, sha256    string
	expires                   time.Time
	done                      bool // promoted; kept so that a retried complete gets 201
}

// uploadTable holds pending uploads and the leases on final keys.
type uploadTable struct {
	mu   sync.Mutex
	m    map[string]*upload
	busy map[string]time.Time // volume + "\x00" + key -> leased until
}

// failMsg answers with a JSON error code clients can act on: exists, busy,
// not-uploaded, mismatch, bad-request, token-expiring, full.
func failMsg(w http.ResponseWriter, code int, msg string) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
	return code
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, rawQuery string, b *Binding, key string, t *token.Token, now time.Time) int {
	q, err := url.ParseQuery(rawQuery)
	switch {
	case err != nil || len(q) != 1:
		return fail(w, http.StatusBadRequest)
	case q.Has("uploads") && q.Get("uploads") == "":
		return s.startUpload(w, r, b, key, t, now)
	case q.Get("complete") != "":
		return s.completeUpload(w, r, b, key, q.Get("complete"), t, now)
	}
	return fail(w, http.StatusBadRequest)
}

func (s *Server) startUpload(w http.ResponseWriter, r *http.Request, b *Binding, key string, t *token.Token, now time.Time) int {
	var req struct {
		Size   int64  `json:"size"`
		MD5    string `json:"md5"`
		SHA256 string `json:"sha256"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Size <= 0 || req.Size > maxUpload || !sha256Hex.MatchString(req.SHA256) {
		return failMsg(w, http.StatusBadRequest, "bad-request")
	}
	md5, err := base64.StdEncoding.DecodeString(req.MD5)
	if err != nil || len(md5) != 16 {
		return failMsg(w, http.StatusBadRequest, "bad-request")
	}
	left := time.Unix(t.Exp, 0).Sub(now)
	if left < minTokenLeft {
		return failMsg(w, http.StatusUnauthorized, "token-expiring")
	}
	st := s.stores[b.Volume]
	if _, _, exists, err := st.Stat(r.Context(), key); err != nil {
		log.Printf("stat %s: %v", key, err)
		return fail(w, http.StatusBadGateway)
	} else if exists {
		return failMsg(w, http.StatusConflict, "exists")
	}
	idb := make([]byte, 16)
	rand.Read(idb)
	id := hex.EncodeToString(idb)
	expiry := min(s.urlLife, left)
	u := &upload{volume: b.Volume, key: key, staging: stagingPrefix + "/" + id, sub: t.Sub, size: req.Size,
		md5Hex: hex.EncodeToString(md5), md5B64: req.MD5, sha256: req.SHA256, expires: now.Add(expiry + completeGrace)}
	loc, err := st.Presign(r.Context(), http.MethodPut, u.staging, expiry, http.Header{"Content-Md5": {req.MD5}})
	if err != nil {
		log.Printf("presign %s: %v", u.staging, err)
		return fail(w, http.StatusBadGateway)
	}
	if !s.uploads.add(id, u, now, s.stores) {
		return failMsg(w, http.StatusServiceUnavailable, "full")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"id": id, "url": loc, "method": http.MethodPut,
		"headers": map[string]string{"Content-MD5": req.MD5}, "expires": now.Add(expiry).UTC().Format(time.RFC3339),
		"complete_by": u.expires.UTC().Format(time.RFC3339)})
	return http.StatusCreated
}

func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request, b *Binding, key, id string, t *token.Token, now time.Time) int {
	u := s.uploads.get(id)
	if u == nil || u.volume != b.Volume || u.key != key || u.sub != t.Sub || now.After(u.expires) {
		return fail(w, http.StatusNotFound)
	}
	if !s.uploads.lease(u.volume, u.key, now) {
		return failMsg(w, http.StatusConflict, "busy")
	}
	held := false // set when the lease must outlive this request
	defer func() {
		if !held {
			s.uploads.release(u.volume, u.key)
		}
	}()
	if s.uploads.isDone(id) {
		return promoted(w, u)
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(copyTimeout + 2*time.Minute))
	// The copy must not stop with the request: a copy landing after a 502 and a
	// released lease could overwrite the next writer.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Minute)
	defer cancel()
	st := s.stores[u.volume]
	drop := func(code int, msg string) int {
		if err := st.Remove(ctx, u.staging); err != nil {
			log.Printf("remove %s: %v", u.staging, err)
		}
		s.uploads.remove(id)
		return failMsg(w, code, msg)
	}
	ours := func(size int64, etag string) bool { return size == u.size && etag == u.md5Hex }
	done := func() int {
		if err := st.Remove(ctx, u.staging); err != nil {
			log.Printf("remove %s: %v", u.staging, err)
		}
		s.uploads.markDone(id)
		return promoted(w, u)
	}
	if fsize, fetag, exists, err := st.Stat(ctx, u.key); err != nil {
		return fail(w, http.StatusBadGateway)
	} else if exists && ours(fsize, fetag) {
		return done() // an earlier complete landed, and its answer was lost
	} else if exists {
		return drop(http.StatusConflict, "exists") // first writer wins
	}
	size, etag, ok, err := st.Stat(ctx, u.staging)
	switch {
	case err != nil:
		return fail(w, http.StatusBadGateway)
	case !ok:
		return failMsg(w, http.StatusConflict, "not-uploaded")
	case !ours(size, etag):
		return drop(http.StatusUnprocessableEntity, "mismatch")
	}
	cctx, ccancel := context.WithTimeout(context.WithoutCancel(r.Context()), copyTimeout)
	copyErr := st.Copy(cctx, u.staging, etag, u.key, map[string]string{"declared-sha256": u.sha256})
	ccancel()
	// Settle the outcome from the final object itself, whatever the copy said.
	fsize, fetag, fok, err := st.Stat(ctx, u.key)
	switch {
	case err != nil || !fok && copyErr != nil:
		// the copy may still land: keep the name leased until it no longer can
		log.Printf("promote %s: copy: %v; stat: %v", u.key, copyErr, err)
		held = true
		s.uploads.hold(u.volume, u.key, now.Add(copyTimeout))
		return fail(w, http.StatusBadGateway) // staging kept: the client may retry later
	case !fok:
		log.Printf("promote %s: the copy reported success but wrote nothing", u.key)
		return fail(w, http.StatusBadGateway)
	case !ours(fsize, fetag):
		// Ours only if it equals the staged object now (a backend ignoring the copy
		// condition took swapped bytes); anything else is not ours to delete.
		ssize, setag, sok, _ := st.Stat(ctx, u.staging)
		if sok && ssize == fsize && setag == fetag {
			if err := st.Remove(ctx, u.key); err != nil {
				log.Printf("promote %s: swapped bytes copied and NOT removed: %v", u.key, err)
				return fail(w, http.StatusBadGateway)
			}
			return drop(http.StatusUnprocessableEntity, "mismatch")
		}
		log.Printf("promote %s: another object appeared during the copy; left alone", u.key)
		return drop(http.StatusConflict, "exists")
	}
	return done()
}

func promoted(w http.ResponseWriter, u *upload) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"declared-sha256": u.sha256})
	return http.StatusCreated
}

// add records an upload, first dropping expired ones (their staging objects are
// removed in the background; a bucket lifecycle rule catches the rest). False
// when the table, or the subject's share of it, is full.
func (ut *uploadTable) add(id string, u *upload, now time.Time, stores map[string]objectStore) bool {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	if ut.m == nil {
		ut.m = map[string]*upload{}
	}
	mine, pending := 0, 0
	for oid, o := range ut.m {
		if now.After(o.expires) {
			delete(ut.m, oid)
			if !o.done {
				go func(st objectStore, key string) {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					st.Remove(ctx, key)
				}(stores[o.volume], o.staging)
			}
		} else if !o.done {
			pending++
			if o.sub == u.sub {
				mine++
			}
		}
	}
	if pending >= maxPending || mine >= maxPerSubject {
		return false
	}
	ut.m[id] = u
	return true
}

func (ut *uploadTable) get(id string) *upload {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	return ut.m[id]
}

func (ut *uploadTable) isDone(id string) bool {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	return ut.m[id] != nil && ut.m[id].done
}

func (ut *uploadTable) markDone(id string) {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	if u := ut.m[id]; u != nil {
		u.done = true
	}
}

func (ut *uploadTable) remove(id string) {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	delete(ut.m, id)
}

func (ut *uploadTable) lease(volume, key string, now time.Time) bool {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	if ut.busy == nil {
		ut.busy = map[string]time.Time{}
	}
	k := volume + "\x00" + key
	if until, ok := ut.busy[k]; ok && now.Before(until) {
		return false
	}
	ut.busy[k] = now.Add(24 * time.Hour) // until released
	return true
}

// hold keeps a lease until a given time: a copy that failed may still land.
func (ut *uploadTable) hold(volume, key string, until time.Time) {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	ut.busy[volume+"\x00"+key] = until
}

func (ut *uploadTable) release(volume, key string) {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	delete(ut.busy, volume+"\x00"+key)
}
