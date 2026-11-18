// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/token"
)

// gcJobs runs the admin API's collections, one at a time, each plan kept in dir
// (-data/gc): <id>.json as -gc-out writes it, <id>.summary.json what it found.
type gcJobs struct {
	mu  sync.Mutex
	dir string
	job *GCJob // the running one, or the last
}

// GCJob is a collection's step the admin API started.
type GCJob struct {
	ID      string     `json:"id"`   // its plan's
	Kind    string     `json:"kind"` // plan
	By      string     `json:"by"`
	Started time.Time  `json:"started"`
	Ended   *time.Time `json:"ended,omitempty"` // nil: running
	Error   string     `json:"error,omitempty"`
}

// GCSummary is a plan the admin API made: by bucket, what goes and why one is refused.
type GCSummary struct {
	ID      string        `json:"id"`
	By      string        `json:"by"`
	Planned time.Time     `json:"planned"`
	Options gcFileOptions `json:"options"`
	Buckets []*GCPlan     `json:"buckets"`
	Files   int           `json:"files"` // to go: those of the buckets not refused
	Bytes   int64         `json:"bytes"`
}

var gcID = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$`)

func openGCJobs(dir string) (*gcJobs, error) {
	return &gcJobs{dir: dir}, os.MkdirAll(dir, 0o750)
}

// start records a job of kind for its plan id, unless one runs: then false.
func (g *gcJobs) start(kind, id, by string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.job != nil && g.job.Ended == nil {
		return false
	}
	g.job = &GCJob{ID: id, Kind: kind, By: by, Started: now.UTC()}
	return true
}

func (g *gcJobs) end(err error, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	at := now.UTC()
	g.job.Ended = &at
	if err != nil {
		g.job.Error = err.Error()
	}
}

func (g *gcJobs) current() *GCJob {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.job == nil {
		return nil
	}
	j := *g.job
	return &j
}

// save writes a plan's file, then its summary: a plan without one is not done.
func (g *gcJobs) save(id, by string, plans []*GCPlan, o GCOptions, now time.Time) error {
	if err := writeGCFile(filepath.Join(g.dir, id+".json"), plans, o, now); err != nil {
		return err
	}
	sum := GCSummary{ID: id, By: by, Planned: now.UTC(), Options: fileOptions(o), Buckets: plans}
	for _, p := range plans {
		for _, a := range p.Arches {
			if p.Refused == "" {
				sum.Files, sum.Bytes = sum.Files+a.Sweep, sum.Bytes+a.SweepBytes
			}
		}
	}
	b, err := json.Marshal(sum)
	if err == nil {
		err = writeFile(filepath.Join(g.dir, id+".summary.json"), b, 0o644)
	}
	if err == nil {
		g.prune(gcKept)
		log.Printf("admin: collection %s planned: %d files to go (%s)", id, sum.Files, bytesOf(sum.Bytes))
	}
	return err
}

// gcKept is how many plans -data/gc keeps: older ones are removed as a new one is made.
const gcKept = 20

// ids are the plans' ids, the newest first.
func (g *gcJobs) ids() ([]string, error) {
	es, err := os.ReadDir(g.dir)
	var ids []string
	for _, e := range es {
		if id, ok := strings.CutSuffix(e.Name(), ".summary.json"); ok && gcID.MatchString(id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids) // they begin with their time
	slices.Reverse(ids)
	return ids, err
}

func (g *gcJobs) prune(keep int) {
	ids, err := g.ids()
	for _, id := range ids[min(keep, len(ids)):] {
		for _, f := range []string{id + ".summary.json", id + ".json"} { // its summary first: a plan without one is not listed
			if e := os.Remove(filepath.Join(g.dir, f)); e != nil && !errors.Is(e, os.ErrNotExist) {
				err = e
			}
		}
	}
	if err != nil {
		log.Printf("collection plans in %s not all removed: %v", g.dir, err)
	}
}

// plans are the summaries of the last n plans, the newest first.
func (g *gcJobs) plans(n int) ([]GCSummary, error) {
	ids, err := g.ids()
	if err != nil {
		return nil, err
	}
	out := []GCSummary{}
	for _, id := range ids[:min(n, len(ids))] {
		var sum GCSummary
		b, err := os.ReadFile(filepath.Join(g.dir, id+".summary.json"))
		if err == nil {
			err = json.Unmarshal(b, &sum)
		}
		if err != nil {
			log.Printf("collection plan %s: %v", id, err) // left out, not the others with it
			continue
		}
		out = append(out, sum)
	}
	return out, nil
}

// adminGCPlan starts a plan (PUT {"grace", "read", "reads", "keep_builds", "max"},
// -gc's defaults for those left out) in the background: 202 {"id"}; 409 while a job runs.
func (s *Server) adminGCPlan(w http.ResponseWriter, r *http.Request, t *token.Token) int {
	var req struct {
		Grace      *string  `json:"grace"`
		Read       *string  `json:"read"`
		Reads      *int     `json:"reads"`
		KeepBuilds *int     `json:"keep_builds"`
		Max        *float64 `json:"max"`
	}
	if !readJSON(w, r, &req) {
		return failMsg(w, http.StatusBadRequest, "body")
	}
	if s.gc == nil || s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	o := DefaultGC
	for name, d := range map[string]struct {
		v   *string
		out *time.Duration
	}{"grace": {req.Grace, &o.Grace}, "read": {req.Read, &o.Read}} {
		if d.v != nil {
			v, err := time.ParseDuration(*d.v)
			if err != nil {
				return failMsg(w, http.StatusBadRequest, name)
			}
			*d.out = v
		}
	}
	if req.Reads != nil {
		o.Reads = *req.Reads
	}
	if req.KeepBuilds != nil {
		o.KeepBuilds = *req.KeepBuilds
	}
	if req.Max != nil {
		o.Max = *req.Max
	}
	if err := checkGCOptions(o); err != nil {
		msg := strings.NewReplacer("-gc-keep-builds", "keep_builds", "-gc-", "").Replace(err.Error())
		return failMsg(w, http.StatusBadRequest, msg)
	}
	now := s.now()
	id := now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(randomBytes(3))
	if !s.gc.start("plan", id, t.Sub, now) {
		return failMsg(w, http.StatusConflict, "a collection job runs")
	}
	log.Printf("admin: %q plans collection %s with %+v", t.Sub, id, fileOptions(o))
	go func() { // not the request's: a plan outlives it, unbounded as -gc's
		plans, err := s.PlanGC(context.Background(), o)
		if err == nil {
			err = s.gc.save(id, t.Sub, plans, o, now)
		}
		if err != nil {
			log.Printf("admin: collection %s: %v", id, err)
		}
		s.gc.end(err, s.now())
	}()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"id": id})
	return http.StatusAccepted
}

// adminGC answers the job running (or the last) and the last 10 plans.
func (s *Server) adminGC(w http.ResponseWriter) int {
	if s.gc == nil {
		return fail(w, http.StatusNotFound)
	}
	plans, err := s.gc.plans(10)
	if err != nil {
		log.Printf("admin gc: %v", err)
		return fail(w, http.StatusInternalServerError)
	}
	return writeJSON(w, map[string]any{"job": s.gc.current(), "plans": plans})
}

// adminGCFiles answers a plan's files to go (?id=, offset, limit: 100, at most 500).
func (s *Server) adminGCFiles(w http.ResponseWriter, rawQuery string) int {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return failMsg(w, http.StatusBadRequest, "query")
	}
	id, offset, limit := q.Get("id"), 0, 100
	if !gcID.MatchString(id) {
		return failMsg(w, http.StatusBadRequest, "id")
	}
	for name, v := range map[string]*int{"offset": &offset, "limit": &limit} {
		if q.Has(name) {
			if *v, err = strconv.Atoi(q.Get(name)); err != nil || *v < 0 || name == "limit" && (*v < 1 || *v > searchLimit) {
				return failMsg(w, http.StatusBadRequest, name)
			}
		}
	}
	if s.gc == nil {
		return fail(w, http.StatusNotFound)
	}
	var f gcFile
	_, err = os.Stat(filepath.Join(s.gc.dir, id+".summary.json")) // done: its summary written
	var b []byte
	if err == nil {
		b, err = os.ReadFile(filepath.Join(s.gc.dir, id+".json"))
	}
	if errors.Is(err, os.ErrNotExist) {
		return fail(w, http.StatusNotFound)
	} else if err == nil {
		err = json.Unmarshal(b, &f)
	}
	if err != nil {
		log.Printf("admin gc files: %v", err)
		return fail(w, http.StatusInternalServerError)
	}
	page := f.Files[min(offset, len(f.Files)):min(offset+limit, len(f.Files))]
	return writeJSON(w, map[string]any{"total": len(f.Files), "files": page})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
