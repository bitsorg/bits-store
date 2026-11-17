// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
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

	"github.com/bitsorg/bits-store/internal/index"
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
	{"bits_store_manifest_objects", "gauge", "Objects under an architecture by the certified build first listing them."},
	{"bits_store_manifest_bytes", "gauge", "Bytes under an architecture by the certified build first listing them."},
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
		if err := s.collectPackages(ctx, bucket, vol, tars[bucket], add); err != nil {
			return nil, err
		}
		add("bits_store_index_drift", vol+`,kind="missing"}`, d.Missing)
		add("bits_store_index_drift", vol+`,kind="changed"}`, d.Changed)
		add("bits_store_index_drift", vol+`,kind="extra"}`, d.Extra)
		add("bits_store_index_verified_seconds", vol+"}", at.Unix())
	}
	add("bits_store_index_errors_total", "", s.index.Errors())
	return m, nil
}

// collectPackages sums a bucket's packages (under its tarballs prefixes) by
// architecture, and by the certified build first listing each (by architecture and
// hash): certified by a verified common manifest, by any without manifest keys; the
// rest is "(uncertified)", or "(restricted)" behind a gate (never in a manifest). One
// pass, so that both splits add up to the same.
func (s *Server) collectPackages(ctx context.Context, bucket, vol string, prefixes []string,
	add func(name, labels string, v int64)) error {
	owner, signed, err := s.index.Certified(ctx, bucket, s.manifestKeys.IDs())
	if err != nil {
		return err
	}
	type key struct{ build, arch string }
	sums := map[key][2]int64{}
	for _, p := range prefixes {
		skip := len(p) + 1
		if p == "" {
			skip = 0
		}
		grouped := s.grouped(bucket, p)
		err := s.index.Each(ctx, bucket, p, func(o index.Object) {
			k, size := o.Key[skip:], o.Size
			if grouped {
				_, k, _ = strings.Cut(k, "/") // <group>/ first
			}
			seg := strings.SplitN(k, "/", 6) // <arch>/store/<h2>/<hash>/<file>
			if seg[0] == "" {
				return
			}
			b := "(uncertified)"
			if grouped {
				b = "(restricted)"
			} else if len(seg) >= 5 && seg[1] == "store" {
				b = cmp.Or(owner[[2]string{seg[0], seg[3]}], b)
			}
			c := sums[key{b, seg[0]}]
			sums[key{b, seg[0]}] = [2]int64{c[0] + 1, c[1] + size}
		})
		if err != nil {
			return err
		}
	}
	byArch := map[string][2]int64{}
	for k, c := range sums {
		byArch[k.arch] = [2]int64{byArch[k.arch][0] + c[0], byArch[k.arch][1] + c[1]}
	}
	for _, a := range slices.Sorted(maps.Keys(byArch)) {
		l := vol + ",arch=" + quote(a) + "}"
		add("bits_store_objects", l, byArch[a][0])
		add("bits_store_bytes", l, byArch[a][1])
	}
	keys := slices.SortedFunc(maps.Keys(sums), func(a, b key) int {
		return cmp.Or(strings.Compare(a.build, b.build), strings.Compare(a.arch, b.arch))
	})
	for _, k := range keys {
		l := fmt.Sprintf("%s,manifest=%s,arch=%s,signed=\"%d\"}", vol, quote(k.build), quote(k.arch), b2i(signed[k.build]))
		add("bits_store_manifest_objects", l, sums[k][0])
		add("bits_store_manifest_bytes", l, sums[k][1])
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
