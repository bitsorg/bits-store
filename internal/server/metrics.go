// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// metricsEvery is how often /metrics (and the admin summary) is computed again: the
// store's totals change slowly, and on a large index one computation is a heavy scan.
const metricsEvery = 15 * time.Minute

// label quotes a label value as the text format has it: \\, \" and \n only.
var label = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func quote(v string) string { return `"` + label.Replace(v) + `"` }

// The metrics, in order: name, type, help.
var metricsDoc = [][3]string{
	{"bits_store_objects", "gauge", "Objects under an architecture."},
	{"bits_store_bytes", "gauge", "Bytes under an architecture."},
	{"bits_store_objects_total", "gauge", "Objects in the bucket."},
	{"bits_store_bytes_total", "gauge", "Bytes in the bucket."},
	{"bits_store_content_objects", "gauge", "Objects in the bucket under a key prefix of its bindings, not under a longer one (binding \"(none)\": the rest)."},
	{"bits_store_content_bytes", "gauge", "Bytes in the bucket under a key prefix of its bindings, not under a longer one (binding \"(none)\": the rest)."},
	{"bits_store_manifest_objects", "gauge", "Objects under an architecture by the certified build first listing them."},
	{"bits_store_manifest_bytes", "gauge", "Bytes under an architecture by the certified build first listing them."},
	{"bits_store_index_drift", "gauge", "What the last listing found the index to differ in."},
	{"bits_store_index_verified_seconds", "gauge", "When the last listing began (Unix time)."},
	{"bits_store_index_errors_total", "counter", "The service's writes the index failed to record."},
	{"bits_store_git_repositories", "gauge", "Repositories a git binding mirrors, by host (on -data)."},
	{"bits_store_git_bytes", "gauge", "Bytes of a git binding's repositories, by host (on -data)."},
	{"bits_store_data_size_bytes", "gauge", "Size of the file system -data is on."},
	{"bits_store_data_free_bytes", "gauge", "Bytes free on the file system -data is on."},
}

// metrics answers /metrics from the index (Prometheus text).
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	body, err := s.scrape.get(r.Context(), s.now(), metricsEvery, s.now, func(ctx context.Context) (string, error) {
		m, err := s.collect(ctx)
		if err != nil {
			log.Printf("metrics: %v", err)
			return "", err
		}
		var b strings.Builder
		for _, d := range metricsDoc {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", d[0], d[2], d[0], d[1])
			for _, l := range m[d[0]] {
				b.WriteString(d[0] + l + "\n")
			}
		}
		return b.String(), nil
	})
	if err != nil {
		return fail(w, http.StatusInternalServerError) // logged when computed; a scraper that gave up: never seen
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprint(w, body)
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
		if err := s.collectContent(ctx, bucket, vol, c, add); err != nil {
			return nil, err
		}
		if err := s.collectPackages(ctx, bucket, vol, tars[bucket], add); err != nil {
			return nil, err
		}
		add("bits_store_index_drift", vol+`,kind="missing"}`, d.Missing)
		add("bits_store_index_drift", vol+`,kind="changed"}`, d.Changed)
		add("bits_store_index_drift", vol+`,kind="extra"}`, d.Extra)
		add("bits_store_index_verified_seconds", vol+"}", at.Unix())
	}
	add("bits_store_index_errors_total", "", s.index.Errors())
	if s.git.root != "" {
		s.collectGit(add)
	}
	return m, nil
}

// collectContent splits a bucket's total by its bindings' key prefixes, each without
// what a longer one inside it holds; the rest is binding "(none)". Labels: the key
// prefix, its bindings' path prefixes and its format.
func (s *Server) collectContent(ctx context.Context, bucket, vol string, total index.Count,
	add func(name, labels string, v int64)) error {
	paths, format := map[string][]string{}, map[string]string{}
	for _, b := range s.bindings {
		if s.place[b.Volume] != bucket {
			continue
		}
		p := strings.Trim(b.KeyPrefix, "/")
		if !slices.Contains(paths[p], b.Prefix) {
			paths[p] = append(paths[p], b.Prefix)
		}
		format[p] = cmp.Or(format[p], b.Format)
	}
	within := func(q, p string) bool { return q != p && (p == "" || strings.HasPrefix(q, p+"/")) }
	ps := slices.SortedFunc(maps.Keys(paths), func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	own, rest := map[string]index.Count{}, total
	for _, p := range ps { // longest first: what is inside p is known
		c, err := s.index.Under(ctx, bucket, p)
		if err != nil {
			return err
		}
		for q, o := range own {
			if within(q, p) {
				c.Objects, c.Bytes = c.Objects-o.Objects, c.Bytes-o.Bytes
			}
		}
		own[p] = c
		rest.Objects, rest.Bytes = rest.Objects-c.Objects, rest.Bytes-c.Bytes
	}
	line := func(p, paths, f string, c index.Count) {
		l := fmt.Sprintf("%s,key_prefix=%s,binding=%s,format=%s}", vol, quote(p), quote(paths), quote(f))
		add("bits_store_content_objects", l, c.Objects)
		add("bits_store_content_bytes", l, c.Bytes)
	}
	for _, p := range slices.Sorted(maps.Keys(own)) {
		line(p, strings.Join(paths[p], ","), format[p], own[p])
	}
	if _, ok := own[""]; !ok {
		line("", "(none)", "", rest)
	}
	return nil
}

// collectGit is each git binding's repositories and their bytes on -data, by host,
// and the size and free bytes of the file system -data is on.
func (s *Server) collectGit(add func(name, labels string, v int64)) {
	for _, b := range s.bindings {
		if b.Format != "git" {
			continue
		}
		dir := filepath.Join(s.git.root, filepath.FromSlash(b.KeyPrefix))
		repos, size := map[string]int64{}, map[string]int64{}
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			rel, _ := filepath.Rel(dir, p)
			host, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
			if err != nil || rel == "." {
				return nil
			}
			if d.IsDir() && strings.HasSuffix(d.Name(), ".git") {
				repos[host]++
			} else if i, err := d.Info(); err == nil && d.Type().IsRegular() {
				size[host] += i.Size()
			}
			return nil
		})
		for _, h := range slices.Sorted(maps.Keys(size)) {
			l := "{binding=" + quote(b.Prefix) + ",host=" + quote(h) + "}"
			add("bits_store_git_repositories", l, repos[h])
			add("bits_store_git_bytes", l, size[h])
		}
	}
	var st syscall.Statfs_t
	if syscall.Statfs(s.git.root, &st) == nil {
		add("bits_store_data_size_bytes", "", int64(st.Blocks)*int64(st.Bsize))
		add("bits_store_data_free_bytes", "", int64(st.Bavail)*int64(st.Bsize))
	}
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
