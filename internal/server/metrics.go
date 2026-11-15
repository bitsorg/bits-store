// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const metricsEvery = time.Minute // scrapes within it share one answer

// metricsCache is the last answer: one computation at a time, however many scrape.
type metricsCache struct {
	mu   sync.Mutex
	at   time.Time
	body string
}

// label quotes a label value as the text format has it: \\, \" and \n only.
var label = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func quote(v string) string { return `"` + label.Replace(v) + `"` }

// The metrics, in order: name, type, help.
var metricsDoc = [][3]string{
	{"bits_store_objects", "gauge", "Objects under an architecture."},
	{"bits_store_bytes", "gauge", "Bytes under an architecture."},
	{"bits_store_objects_total", "gauge", "Objects in the bucket."},
	{"bits_store_bytes_total", "gauge", "Bytes in the bucket."},
	{"bits_store_index_drift", "gauge", "What the last listing found the index to differ in."},
	{"bits_store_index_verified_seconds", "gauge", "When the last listing began (Unix time)."},
	{"bits_store_index_errors_total", "counter", "The service's writes the index failed to record."},
}

// metrics answers /metrics from the index (Prometheus text).
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	c := &s.scrape
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := s.now(); c.body == "" || now.Sub(c.at) >= metricsEvery || now.Before(c.at) {
		m, err := s.collect(r.Context())
		if err != nil {
			log.Printf("metrics: %v", err)
			return fail(w, http.StatusInternalServerError)
		}
		var b strings.Builder
		for _, d := range metricsDoc {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", d[0], d[2], d[0], d[1])
			for _, l := range m[d[0]] {
				b.WriteString(d[0] + l + "\n")
			}
		}
		c.at, c.body = now, b.String()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprint(w, c.body)
	return http.StatusOK
}

// collect is each verified bucket's objects and bytes, in all and by architecture
// (under its tarballs bindings' key prefixes), named by its first volume; what its
// last listing found; index errors. Lines by metric, without the name.
func (s *Server) collect(ctx context.Context) (map[string][]string, error) {
	m := map[string][]string{}
	add := func(name, labels string, v int64) { m[name] = append(m[name], labels+" "+strconv.FormatInt(v, 10)) }
	tars := map[string][]string{} // bucket -> its tarballs bindings' key prefixes
	for _, b := range s.bindings {
		at, p := s.place[b.Volume], strings.TrimSuffix(b.KeyPrefix, "/")
		if b.Format == "tarballs" && !slices.Contains(tars[at], p) {
			tars[at] = append(tars[at], p)
		}
	}
	seen := map[string]bool{}
	for _, n := range slices.Sorted(maps.Keys(s.stores)) {
		bucket := s.place[n]
		if s.stores[n].Anonymous() || seen[bucket] {
			continue
		}
		seen[bucket] = true
		at, d, ok, err := s.index.Verified(ctx, bucket)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue // only the service's own writes so far, not the bucket
		}
		vol := "{volume=" + quote(n)
		c, err := s.index.Total(ctx, bucket)
		if err != nil {
			return nil, err
		}
		add("bits_store_objects_total", vol+"}", c.Objects)
		add("bits_store_bytes_total", vol+"}", c.Bytes)
		byArch := map[string][2]int64{}
		for _, p := range tars[bucket] {
			u, err := s.index.Under(ctx, bucket, p)
			if err != nil {
				return nil, err
			}
			for a, c := range u {
				byArch[a] = [2]int64{byArch[a][0] + c.Objects, byArch[a][1] + c.Bytes}
			}
		}
		for _, a := range slices.Sorted(maps.Keys(byArch)) {
			l := vol + ",arch=" + quote(a) + "}"
			add("bits_store_objects", l, byArch[a][0])
			add("bits_store_bytes", l, byArch[a][1])
		}
		add("bits_store_index_drift", vol+`,kind="missing"}`, d.Missing)
		add("bits_store_index_drift", vol+`,kind="changed"}`, d.Changed)
		add("bits_store_index_drift", vol+`,kind="extra"}`, d.Extra)
		add("bits_store_index_verified_seconds", vol+"}", at.Unix())
	}
	add("bits_store_index_errors_total", "", s.index.Errors())
	return m, nil
}
