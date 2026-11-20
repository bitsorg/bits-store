// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/format"
	"github.com/bitsorg/bits-store/internal/index"
	"github.com/bitsorg/bits-store/internal/token"
)

// Writes (ADR 0004 D): a client never gets a URL for a final key.
//
//	POST <path>?uploads          {"size", "md5" (base64), "sha256" (hex)}
//	                             -> 201 {"id", "url", "method", "headers", "expires", "complete_by"}
//	                             (in parts, multipart.go: "part_size", "part_md5" -> "parts";
//	                             a folder's object, format.Folder: "name")
//	PUT  <url> with the headers  (straight to the volume, into STAGING/<id>)
//	POST <path>?complete=<id>    -> 201 promoted (also on a retry), 409 the name exists
//	                                or is being promoted, 422 wrong size or MD5
//
// Size and MD5 are checked; the SHA-256 is the uploader's declaration, kept as
// "declared-sha256" (a tarball's as "sha256", bits' name). First-writer-wins needs one
// instance: the lease is in memory.
const (
	stagingPrefix = "STAGING"
	maxUpload     = 5 << 30 // one presigned PUT; more in parts
	maxPending    = 10000
	maxPerSubject = 100
	completeGrace = time.Hour // after the URL expires, time left to complete
	minTokenLeft  = time.Minute
	copyTimeout   = 10 * time.Minute // and a second per 32 MiB beyond (copyTime)
)

var stepTimeout = time.Minute // a promote's other calls (Stat, Remove), each phase

// completeTime is how long a complete may take: assembly, copy and their checks.
func completeTime(size int64) time.Duration { return 2*copyTime(size) + 5*time.Minute }

// copyTime is how long a promote's server-side copy of size bytes may take.
func copyTime(size int64) time.Duration {
	return copyTimeout + time.Duration(size>>25)*time.Second
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

type upload struct {
	volume, key, staging, sub string
	dir                       string // the folder of a named upload (format.Folder)
	size                      int64
	md5Hex, sha256            string
	meta                      map[string]string // the final object's, with bits-upload
	fetched                   bool              // staged by the server (fetch.go), not a client
	uploadID                  string            // a multipart upload's (multipart.go)
	partSize                  int64
	partMD5                   []string // hex
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

// write takes an upload of key, or of the object of folder dir (format.Folder),
// which the start names ("name").
func (s *Server) write(w http.ResponseWriter, r *http.Request, rawQuery string, b *Binding, key, dir string, t *token.Token, now time.Time) int {
	q, err := url.ParseQuery(rawQuery)
	switch {
	case err != nil || len(q) != 1:
		return fail(w, http.StatusBadRequest)
	case q.Has("uploads") && q.Get("uploads") == "":
		return s.startUpload(w, r, b, key, dir, t, now)
	case q.Get("complete") != "":
		return s.completeUpload(w, r, b, key+dir, q.Get("complete"), t, now)
	}
	return fail(w, http.StatusBadRequest)
}

func (s *Server) startUpload(w http.ResponseWriter, r *http.Request, b *Binding, key, dir string, t *token.Token, now time.Time) int {
	var req struct {
		Name     string   `json:"name"`
		Size     int64    `json:"size"`
		MD5      string   `json:"md5"`
		SHA256   string   `json:"sha256"`
		PartSize int64    `json:"part_size"`
		PartMD5  []string `json:"part_md5"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Size <= 0 || !sha256Hex.MatchString(req.SHA256) || (dir == "") != (req.Name == "") {
		return failMsg(w, http.StatusBadRequest, "bad-request")
	}
	if dir != "" {
		item := format.Item{Dir: b.unprefixed(dir)}
		if _, err := token.ParsePath("/" + req.Name); err != nil || strings.Contains(req.Name, "/") ||
			b.folder.ObjectName(item, req.Name) != nil {
			return failMsg(w, http.StatusBadRequest, "bad-name")
		}
		key = dir + "/" + req.Name
	}
	u := &upload{volume: b.Volume, key: key, dir: dir, sub: t.Sub, size: req.Size, sha256: req.SHA256,
		meta: map[string]string{"declared-sha256": req.SHA256}}
	if dir != "" {
		u.meta = map[string]string{"sha256": "sha256:" + req.SHA256} // as bits' own writers keep it
	}
	if t.Grp != "" {
		u.meta["bits-group"] = url.PathEscape(t.Grp) // its writer (not in a listing)
	}
	if req.PartMD5 != nil {
		var ok bool
		u.partMD5, u.md5Hex, ok = checkParts(req.Size, req.PartSize, req.PartMD5)
		if !ok || req.MD5 != "" {
			return failMsg(w, http.StatusBadRequest, "bad-request")
		}
		u.partSize = req.PartSize
	} else {
		md5, err := base64.StdEncoding.DecodeString(req.MD5)
		if err != nil || len(md5) != 16 || req.Size > maxUpload || req.PartSize != 0 {
			return failMsg(w, http.StatusBadRequest, "bad-request")
		}
		u.md5Hex = hex.EncodeToString(md5)
	}
	left := time.Unix(t.Exp, 0).Sub(now)
	if left < minTokenLeft {
		return failMsg(w, http.StatusUnauthorized, "token-expiring")
	}
	if s.denied(b, "sha256:"+req.SHA256) {
		return failMsg(w, http.StatusForbidden, "denied") // withdrawn: never signed again
	}
	st := s.stores[b.Volume]
	if _, exists, err := st.Stat(r.Context(), key); err != nil {
		s.errorf("volume_request_failed", key, "stat %s: %v", key, err)
		return fail(w, http.StatusBadGateway)
	} else if exists {
		return failMsg(w, http.StatusConflict, "exists")
	}
	if dir != "" {
		if found, err := s.others(r.Context(), b.Volume, dir, ""); err != nil {
			s.errorf("volume_request_failed", dir, "list %s: %v", dir, err)
			return fail(w, http.StatusBadGateway)
		} else if found {
			return failMsg(w, http.StatusConflict, "exists") // under another name
		}
	}
	idb := make([]byte, 16)
	rand.Read(idb)
	id := hex.EncodeToString(idb)
	u.staging = stagingPrefix + "/" + id
	expiry := min(s.urlLife, left)
	if u.partMD5 != nil {
		// parts start one after another: their URLs live a second per 8 MiB longer
		expiry = min(s.urlLife+time.Duration(req.Size>>23)*time.Second, left)
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute)) // up to 6 MB
	}
	u.expires = now.Add(expiry + completeGrace)
	if !s.uploads.add(id, u, now, s.stores) {
		return failMsg(w, http.StatusServiceUnavailable, "full")
	}
	if b.Gate != "" { // signed now (after the subject's limit), kept with it: reused only if it verifies
		arch, rest, _ := strings.Cut(b.unprefixed(dir), "/") // <arch>/store/<h2>/<hash>
		kid, sig, err := s.signer.sign(r.Context(), restrictedStatement(arch, path.Base(rest), t.Grp, req.Name, req.SHA256))
		if err != nil {
			s.uploads.remove(id)
			s.errorf("presign_failed", key, "sign %s: %v", key, err)
			return failMsg(w, http.StatusServiceUnavailable, "unsigned")
		}
		u.meta["bits-signature"] = kid + ":" + base64.StdEncoding.EncodeToString(sig) // read at complete: after the id is sent
	}
	answer := map[string]any{"id": id, "method": http.MethodPut}
	if u.partMD5 != nil {
		parts, err := s.presignParts(r.Context(), u, req.PartMD5, expiry)
		if err != nil {
			s.uploads.remove(id)
			s.errorf("volume_request_failed", u.staging, "start parts %s: %v", u.staging, err)
			return fail(w, http.StatusBadGateway)
		}
		answer["parts"] = parts
	} else {
		loc, err := st.Presign(r.Context(), http.MethodPut, u.staging, expiry, http.Header{"Content-Md5": {req.MD5}})
		if err != nil {
			s.uploads.remove(id)
			s.errorf("presign_failed", u.staging, "presign %s: %v", u.staging, err)
			return fail(w, http.StatusBadGateway)
		}
		answer["url"], answer["headers"] = loc, map[string]string{"Content-MD5": req.MD5}
	}
	answer["expires"] = now.Add(expiry).UTC().Format(time.RFC3339)
	answer["complete_by"] = u.expires.UTC().Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(answer)
	return http.StatusCreated
}

func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request, b *Binding, at, id string, t *token.Token, now time.Time) int {
	u := s.uploads.claim(id, b.Volume, at, t.Sub, now)
	if u == nil {
		return fail(w, http.StatusNotFound)
	}
	if s.denied(b, "sha256:"+u.sha256) && !s.uploads.isDone(id) {
		s.uploads.expire(id) // its staging object removed with the expired ones
		return failMsg(w, http.StatusForbidden, "denied")
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(completeTime(u.size)))
	if u.uploadID != "" && !s.uploads.isDone(id) {
		if code, msg := s.assemble(r.Context(), u, id); code != 0 && msg == "" {
			return fail(w, code)
		} else if code != 0 {
			return failMsg(w, code, msg)
		}
	}
	switch code, msg := s.promote(r.Context(), u, id, now); {
	case code == http.StatusCreated:
		return promoted(w, u)
	case msg == "":
		return fail(w, code)
	default:
		return failMsg(w, code, msg)
	}
}

// promote copies a staged object to its key, first writer wins: 201, or an error
// code with the message for failMsg ("" for none).
func (s *Server) promote(parent context.Context, u *upload, id string, now time.Time) (int, string) {
	place := s.place[u.volume] // the bucket, not the name: a reload may rename a volume
	name := u.key
	if u.dir != "" {
		name = u.dir + "/" // the folder: one object in it
	}
	if !s.uploads.lease(place, name, now) {
		return http.StatusConflict, "busy"
	}
	held := false // set when the lease must outlive this request
	defer func() {
		if !held {
			s.uploads.release(place, name)
		}
	}()
	if s.uploads.isDone(id) {
		return http.StatusCreated, ""
	}
	// The copy must not stop with the request: a copy landing after a 502 and a
	// released lease could overwrite the next writer.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), stepTimeout)
	defer cancel()
	st := s.stores[u.volume]
	drop := func(code int, msg string) (int, string) {
		if err := st.Remove(ctx, u.staging); err != nil {
			s.warnf("staging_left", u.staging, "remove %s: %v", u.staging, err)
		}
		s.uploads.remove(id)
		return code, msg
	}
	// A client's staged object is its MD5; one the server fetched, or a copy in
	// parts (no MD5 for ETag), is marked as ours by the upload id in its metadata.
	marked := func(i objInfo) bool { return i.Size == u.size && i.Meta["bits-upload"] == id }
	staged := func(i objInfo) bool { return i.Size == u.size && i.ETag == u.md5Hex || u.fetched && marked(i) }
	// a copy of an object in parts may get a new ETag: ours by its marker too
	ours := func(i objInfo) bool { return staged(i) || (u.size > maxCopy || u.uploadID != "") && marked(i) }
	// the final object's own writer: the same bytes again keep the first
	done := func(fi objInfo) (int, string) {
		s.uploads.markDone(id) // first: a retry must not look for the staged object
		if s.index != nil {
			o := index.Object{Key: u.key, Size: fi.Size, ETag: fi.ETag, Mtime: now, SHA256: u.sha256, Grp: writer(fi)}
			if err := s.index.Put(ctx, place, o, s.now()); err != nil {
				s.errorf("index_write_failed", u.key, "index %s: %v", u.key, err) // a verify adds it
			}
		}
		if u.dir != "" {
			s.found.stored(s, u.volume, u.dir, u.key, now)
		}
		if err := st.Remove(ctx, u.staging); err != nil {
			s.warnf("staging_left", u.staging, "remove %s: %v", u.staging, err)
		}
		return http.StatusCreated, ""
	}
	if u.dir != "" {
		if found, err := s.others(ctx, u.volume, u.dir, u.key); err != nil {
			return http.StatusBadGateway, ""
		} else if found {
			return drop(http.StatusConflict, "exists") // another name came first
		}
	}
	if fi, exists, err := st.Stat(ctx, u.key); err != nil {
		return http.StatusBadGateway, ""
	} else if exists && ours(fi) {
		return done(fi) // an earlier complete landed, and its answer was lost
	} else if exists {
		return drop(http.StatusConflict, "exists") // first writer wins
	}
	si, ok, err := st.Stat(ctx, u.staging)
	switch {
	case err != nil:
		return http.StatusBadGateway, ""
	case !ok:
		return http.StatusConflict, "not-uploaded"
	case !staged(si):
		return drop(http.StatusUnprocessableEntity, "mismatch")
	}
	meta := map[string]string{}
	for k, v := range u.meta {
		meta[k] = v
	}
	meta["bits-upload"] = id
	cctx, ccancel := context.WithTimeout(context.WithoutCancel(parent), copyTime(u.size))
	copyErr := st.Copy(cctx, u.staging, si.ETag, u.key, u.size, meta)
	ccancel()
	// the copy may have outlasted ctx: a fresh one for what follows (drop, done too)
	sctx, scancel := context.WithTimeout(context.WithoutCancel(parent), stepTimeout)
	defer scancel()
	ctx = sctx
	// Settle the outcome from the final object itself, whatever the copy said.
	fi, fok, err := st.Stat(ctx, u.key)
	switch {
	case err != nil || !fok && copyErr != nil:
		// the copy may still land: keep the name leased until it no longer can
		s.errorf("promote_failed", u.key, "promote %s: copy: %v; stat: %v", u.key, copyErr, err)
		held = true
		s.uploads.hold(place, name, now.Add(copyTime(u.size)))
		return http.StatusBadGateway, "" // staging kept: the client may retry later
	case !fok:
		s.errorf("promote_failed", u.key, "promote %s: the copy reported success but wrote nothing", u.key)
		return http.StatusBadGateway, ""
	case !ours(fi):
		// Ours only if it equals the staged object now (a backend ignoring the copy
		// condition took swapped bytes); anything else is not ours to delete.
		si, sok, _ := st.Stat(ctx, u.staging)
		if sok && si.Size == fi.Size && si.ETag == fi.ETag {
			if err := st.Remove(ctx, u.key); err != nil {
				s.errorf("promote_failed", u.key, "promote %s: swapped bytes copied and NOT removed: %v", u.key, err)
				return http.StatusBadGateway, ""
			}
			return drop(http.StatusUnprocessableEntity, "mismatch")
		}
		s.warnf("promote_conflict", u.key, "promote %s: another object appeared during the copy; left alone", u.key)
		return drop(http.StatusConflict, "exists")
	}
	return done(fi)
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
			if st := stores[o.volume]; !o.done && st != nil { // a reload may have removed the volume
				go func(st objectStore, key, uploadID string) {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					if uploadID != "" {
						st.AbortMultipart(ctx, key, uploadID)
					}
					st.Remove(ctx, key)
				}(st, o.staging, o.uploadID)
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

// claim returns its owner's pending upload for a complete, kept at least until the
// complete can no longer run; nil when there is none.
func (ut *uploadTable) claim(id, volume, at, sub string, now time.Time) *upload {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	u := ut.m[id]
	if u == nil || u.volume != volume || u.key != at && u.dir != at || u.sub != sub || now.After(u.expires) {
		return nil
	}
	if until := now.Add(completeTime(u.size)); u.expires.Before(until) {
		u.expires = until
	}
	return u
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

func (ut *uploadTable) expire(id string) {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	if u := ut.m[id]; u != nil {
		u.expires = time.Time{}
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

// writer is the group that wrote an object through the service; "": not known.
func writer(fi objInfo) string {
	g, _ := url.PathUnescape(fi.Meta["bits-group"])
	return g
}
