// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// GCOptions bound a collection: packages younger than Grace stay, those read within
// Read, or read at least Reads times within four times Read (0: no such rule), and
// the KeepBuilds newest builds of each package version; it refuses to sweep more
// than Max (a share) of an architecture's packages. List: name the files that would go;
// Out: write them to a file; Apply: delete those of such a file the plan still sweeps.
type GCOptions struct {
	Grace, Read       time.Duration
	Reads, KeepBuilds int
	Max               float64
	List              bool
	Out, Apply        string
}

// GCArch is the plan for one architecture of a bucket's package tree.
type GCArch struct {
	Arch                                    string
	Certified                               bool // a verified common manifest lists packages of it: else nothing goes
	Kept, Young, Read, Newest, Other, Sweep int  // Other: not packages, never swept; Read: read lately; Newest: of the newest builds of their version
	KeptBytes, SweepBytes                   int64
	sweep                                   []index.Object
}

// GCPlan is a bucket's collection, named by its first volume; Refused says why
// nothing of it may be swept.
type GCPlan struct {
	Volume, Refused string
	Arches          []*GCArch
	bucket          string
	mans            []string // its manifests bindings' key prefixes
}

// A package file, as bits' gc.py has it: <arch>/store/<h2>/<hash>/<file>, h2 the hash's start.
var packageKey = regexp.MustCompile(`^([0-9A-Za-z][0-9A-Za-z._+-]*)/store/([0-9A-Za-z]{2})/` +
	`([0-9A-Za-z][0-9A-Za-z._-]*)/[0-9A-Za-z][0-9A-Za-z._+-]*$`)

// PlanGC plans a collection of each bucket with packages, from the index: a package
// goes when its hash is no root (index.Roots), it is older than o.Grace and a verified
// common manifest lists packages of its architecture. Fail-closed: a bucket whose
// index may not be the store (not listed lately, manifests unread, common manifests
// changed since) is refused. A gated binding's builds (one folder per group) have no
// manifests: they go by age, reads and newer builds alone.
func (s *Server) PlanGC(ctx context.Context, o GCOptions) ([]*GCPlan, error) {
	tars, mans, gated, name := map[string][]string{}, map[string][]string{}, map[string][]string{}, map[string]string{}
	for _, b := range s.bindings {
		at, p := s.place[b.Volume], strings.TrimSuffix(b.KeyPrefix, "/")
		if s.stores[b.Volume].Anonymous() {
			continue
		}
		if n, ok := name[at]; !ok || b.Volume < n {
			name[at] = b.Volume
		}
		switch {
		case b.Gate != "":
			gated[at] = append(gated[at], p)
		case b.Format == "tarballs":
			tars[at] = append(tars[at], p)
		case b.Format == "manifests":
			mans[at] = append(mans[at], p)
		}
	}
	var plans []*GCPlan
	for _, bucket := range slices.Sorted(maps.Keys(tars)) {
		p := &GCPlan{Volume: name[bucket], bucket: bucket, mans: mans[bucket]}
		plans = append(plans, p)
		why, err := s.gcRefused(ctx, bucket, p.Volume, mans[bucket])
		if err != nil {
			return nil, err
		}
		p.Refused = why
		if why != "" {
			continue
		}
		roots, certified, err := s.index.Roots(ctx, bucket, s.manifestKeys.IDs())
		if err != nil {
			return nil, err
		}
		if p.Refused, err = s.strayRoots(ctx, bucket, p.Volume, roots); err != nil || p.Refused != "" {
			if err != nil {
				return nil, err
			}
			continue
		}
		if err := s.planTree(ctx, p, tars[bucket], false, roots, certified, o); err != nil {
			return nil, err
		}
	}
	for _, bucket := range slices.Sorted(maps.Keys(gated)) {
		p := &GCPlan{Volume: name[bucket], bucket: bucket}
		plans = append(plans, p)
		why, err := s.listedLately(ctx, bucket)
		if p.Refused = why; err != nil {
			return nil, err
		}
		if why == "" {
			if err := s.planTree(ctx, p, gated[bucket], true, nil, nil, o); err != nil {
				return nil, err
			}
		}
	}
	return plans, nil
}

// planTree plans the packages under prefixes of p's bucket by architecture (by
// group and architecture, a folder each, when grouped: all may go, no roots).
func (s *Server) planTree(ctx context.Context, p *GCPlan, prefixes []string, grouped bool,
	roots, certified map[string]bool, o GCOptions) error {
	oldest := s.now().Add(-o.Grace)
	arches, readSince, popularSince := map[string]*GCArch{}, s.now().Add(-o.Read), s.now().Add(-4*o.Read)
	builds := map[string][]index.Object{} // the package files of each version, by architecture
	for _, prefix := range slices.Compact(slices.Sorted(slices.Values(prefixes))) {
		skip := len(prefix) + 1
		if prefix == "" {
			skip = 0
		}
		err := s.index.Each(ctx, p.bucket, prefix, func(obj index.Object) {
			rest, group := obj.Key[skip:], ""
			if grouped {
				group, rest, _ = strings.Cut(rest, "/")
				group += "/"
			}
			arch, _, _ := strings.Cut(rest, "/")
			a := arches[group+arch]
			if a == nil {
				a = &GCArch{Arch: group + arch, Certified: grouped || certified[arch]}
				arches[group+arch] = a
			}
			m := packageKey.FindStringSubmatch(rest)
			if grouped && !groupName.MatchString(strings.TrimSuffix(group, "/")) {
				m = nil // not under a group: never read through the service, never swept
			}
			switch {
			case m == nil || !strings.HasPrefix(m[3], m[2]):
				a.Other++
			case !a.Certified || roots[strings.ToLower(m[3])]:
				a.Kept++
				a.KeptBytes += obj.Size
			case obj.Mtime.After(oldest):
				a.Young++
			case o.Read > 0 && obj.ReadAt.After(readSince),
				o.Reads > 0 && obj.Reads >= int64(o.Reads) && obj.ReadAt.After(popularSince):
				a.Read++
			default:
				a.sweep = append(a.sweep, obj)
			}
			if m != nil && strings.HasPrefix(m[3], m[2]) { // a package; one named otherwise is its own version
				v := prefix + "\x00" + group + cmp.Or(versionOf(arch, m), "?"+obj.Key)
				builds[v] = append(builds[v], obj)
			}
		})
		if err != nil {
			return err
		}
	}
	newest := newestBuilds(builds, o.KeepBuilds)
	for _, k := range slices.Sorted(maps.Keys(arches)) {
		a := arches[k]
		p.Arches = append(p.Arches, a)
		sweep := a.sweep[:0]
		for _, f := range a.sweep {
			if newest[f.Key] {
				a.Newest++
			} else {
				sweep = append(sweep, f)
				a.Sweep++
				a.SweepBytes += f.Size
			}
		}
		a.sweep = sweep
		if all := a.Kept + a.Young + a.Read + a.Newest + a.Sweep; a.Sweep > 0 && float64(a.Sweep) > o.Max*float64(all) && p.Refused == "" {
			p.Refused = fmt.Sprintf("%s: %d of its %d packages would go, more than %g of them", k, a.Sweep, all, o.Max)
		}
	}
	if since, err := s.index.ReadsSince(ctx); err != nil {
		return err
	} else if o.Read > 0 && s.now().Sub(since) < o.Read && p.Refused == "" {
		p.Refused = fmt.Sprintf("reads are counted since %s only: not before %s (or -gc-read 0)",
			since.UTC().Format(time.DateOnly), since.Add(o.Read).UTC().Format(time.DateOnly))
	}
	return nil
}

// listedLately says why a bucket's index may not stand for it ("" when it may):
// never listed, or not lately.
func (s *Server) listedLately(ctx context.Context, bucket string) (string, error) {
	at, _, ok, err := s.index.Verified(ctx, bucket)
	switch {
	case err != nil:
		return "", err
	case !ok:
		return "it was never listed", nil
	case s.now().Sub(at) > s.verifyEvery+2*time.Hour:
		return fmt.Sprintf("its last listing is %s old", s.now().Sub(at).Round(time.Minute)), nil
	}
	return "", nil
}

// gcRefused says why a bucket's index may not stand for the store, "" when it may:
// no manifest keys, no recent listing, manifests not all read, or the common
// manifests (and their .sig) in the store not those the index read.
func (s *Server) gcRefused(ctx context.Context, bucket, volume string, mans []string) (string, error) {
	keys := s.manifestKeys.IDs()
	if keys == "" {
		return "no manifest_keys: no common manifest is verified", nil
	}
	if why, err := s.listedLately(ctx, bucket); why != "" || err != nil {
		return why, err
	}
	if n, err := s.index.Unread(ctx, bucket); err != nil || n > 0 {
		return fmt.Sprintf("%d manifests could not be read, or not all of their packages", n), err
	}
	for _, p := range mans {
		todo, err := s.index.ManifestsToRead(ctx, bucket, p, keys, s.now(), 1)
		if err != nil || len(todo) > 0 {
			return "manifests not all read yet", err
		}
	}
	commons, err := s.index.Commons(ctx, bucket, keys)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(slices.Collect(maps.Values(commons)), func(c index.Common) bool { return c.Verified }) {
		return "no common manifest verifies with manifest_keys", nil
	}
	// the store now: no common manifest new at the top of a binding, each as read
	st := s.stores[volume]
	for _, p := range mans {
		start := "common-manifest-"
		if p != "" {
			start = p + "/" + start
		}
		names, err := st.List(ctx, start)
		if err != nil {
			return fmt.Sprintf("the common manifests could not be listed: %v", err), nil
		}
		for _, n := range names {
			if _, ok := commons[n]; !ok && strings.HasSuffix(n, ".json") {
				return n + " is new since the index read the manifests", nil
			}
		}
	}
	for _, n := range slices.Sorted(maps.Keys(commons)) {
		for _, f := range []struct{ key, etag string }{{n, commons[n].ETag}, {n + ".sig", commons[n].SigETag}} {
			fi, ok, err := st.Stat(ctx, f.key)
			if err != nil {
				return fmt.Sprintf("%s could not be read: %v", f.key, err), nil
			}
			if !ok {
				fi.ETag = ""
			}
			if fi.ETag != f.etag {
				return f.key + " changed since the index read it", nil
			}
		}
	}
	return "", nil
}

// GC plans a collection with the configuration at path and the index in data (as
// the running service has them), and writes the plan to out: 0 when every bucket
// may be swept, 2 when one is refused, 1 on an error. It deletes nothing.
func GC(path, data string, o GCOptions, out io.Writer) int {
	c, err := LoadConfig(path)
	switch {
	case err != nil:
	case data == "":
		err = errors.New("-gc needs -data, the service's index")
	case o.Grace <= 0:
		err = errors.New("-gc-grace: a positive duration")
	case !(o.Max > 0 && o.Max <= 1): // NaN too
		err = errors.New("-gc-max: a share above 0, at most 1")
	case o.Read < 0 || o.Reads < 0 || o.Read > 10*365*24*time.Hour:
		err = errors.New("-gc-read, -gc-reads: 0 (no such rule) or more; -gc-read at most ten years")
	case o.KeepBuilds < 0:
		err = errors.New("-gc-keep-builds: 0 (no such rule) or more")
	case o.Read == 0 && o.Reads > 0:
		err = errors.New("-gc-reads counts within four times -gc-read: with -gc-read 0, set -gc-reads 0")
	case o.Out != "" && o.Apply != "":
		err = errors.New("-gc-out writes a plan, -gc-apply deletes what one names: not both")
	}
	var s *Server
	if err == nil {
		s, err = New(c)
	}
	if err == nil {
		s.index, err = index.OpenReadOnly(filepath.Join(data, "index.db"))
	}
	var plans []*GCPlan
	if err == nil {
		defer s.index.Close()
		plans, err = s.PlanGC(context.Background(), o)
	}
	if err == nil && o.Apply != "" {
		return s.ApplyGC(context.Background(), plans, o, o.Apply, out)
	}
	if err == nil && o.Out != "" {
		err = writeGCFile(o.Out, plans, o, s.now())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gc:", err)
		return 1
	}
	return writePlan(out, plans, o)
}

// gcFile is a plan's files to go, as -gc-out writes it for review and -gc-apply reads it.
type gcFile struct {
	Planned time.Time     `json:"planned"`
	Options gcFileOptions `json:"options"` // -gc-apply plans again with the same
	Files   []gcFileEntry `json:"files"`
}

type gcFileOptions struct {
	Grace      string  `json:"grace"`
	Read       string  `json:"read"`
	Reads      int     `json:"reads"`
	KeepBuilds int     `json:"keep_builds"`
	Max        float64 `json:"max"`
}

func fileOptions(o GCOptions) gcFileOptions {
	return gcFileOptions{o.Grace.String(), o.Read.String(), o.Reads, o.KeepBuilds, o.Max}
}

type gcFileEntry struct {
	Volume string    `json:"volume"`
	Bucket string    `json:"bucket"` // the volume's endpoint and bucket
	Key    string    `json:"key"`
	Size   int64     `json:"size"`
	ETag   string    `json:"etag"`
	Reads  int64     `json:"reads"`   // as planned: a read since keeps it
	ReadAt time.Time `json:"read_at"` // zero: none
}

// gcPlanLife is how old a plan file -gc-apply takes may be.
const gcPlanLife = 7 * 24 * time.Hour

// writeGCFile writes the files of the plans that may go now (none of a refused one).
func writeGCFile(name string, plans []*GCPlan, o GCOptions, now time.Time) error {
	f := gcFile{Planned: now.UTC(), Options: fileOptions(o), Files: []gcFileEntry{}}
	for _, p := range plans {
		for _, a := range p.Arches {
			for _, obj := range a.sweep {
				if p.Refused == "" {
					f.Files = append(f.Files, gcFileEntry{p.Volume, p.bucket, obj.Key, obj.Size, obj.ETag, obj.Reads, obj.ReadAt})
				}
			}
		}
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".gc-plan-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// readGCFile reads a plan file -gc-out wrote, with options o, at most gcPlanLife ago.
func readGCFile(name string, o GCOptions, now time.Time) (gcFile, error) {
	var f gcFile
	b, err := os.ReadFile(name)
	if err != nil {
		return f, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || dec.More() {
		return f, fmt.Errorf("not a plan -gc-out wrote: %v", cmp.Or(err, errors.New("more after it")))
	}
	switch {
	case f.Options != fileOptions(o):
		return f, fmt.Errorf("planned with other options (%+v): apply with the same", f.Options)
	case f.Planned.After(now.Add(time.Hour)), now.Sub(f.Planned) > gcPlanLife:
		return f, fmt.Errorf("planned %s: not within %s", f.Planned.Format(time.RFC3339), gcPlanLife)
	}
	return f, nil
}

// ApplyGC deletes the files of the plan file at name that plans (made now, with o)
// still sweep, each as it was planned (size and ETag, in the index and the bucket),
// not read nor listed by a manifest since (checked again as it goes); anything else
// stays and is said. 0: done; 2: a bucket refused, or its manifests changed, now
// (what is left of it stays); 1: an error (the plan file, a file not deleted).
func (s *Server) ApplyGC(ctx context.Context, plans []*GCPlan, o GCOptions, name string, out io.Writer) int {
	f, err := readGCFile(name, o, s.now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "gc: %s: %v\n", name, err)
		return 1
	}
	byBucket, now, code := map[string]*GCPlan{}, map[[2]string]index.Object{}, 0
	for _, p := range plans {
		byBucket[p.bucket] = p
		if p.Refused != "" {
			code = 2
			fmt.Fprintf(out, "volume %q: nothing goes: %s\n", p.Volume, p.Refused)
			continue
		}
		for _, a := range p.Arches {
			for _, obj := range a.sweep {
				now[[2]string{p.bucket, obj.Key}] = obj
			}
		}
	}
	var deleted, kept, failed int
	var freed int64
	roots, checked := map[string]map[string]bool{}, map[string]time.Time{} // per bucket
	keep := func(e gcFileEntry, why string) {
		fmt.Fprintf(out, "kept: %s %s: %s\n", e.Volume, e.Key, why)
		kept++
	}
	for _, e := range f.Files {
		p, planned := byBucket[e.Bucket], now[[2]string{e.Bucket, e.Key}]
		switch {
		case p == nil:
			keep(e, "no such volume now")
			continue
		case p.Refused != "":
			keep(e, "its volume is refused now")
			continue
		case planned.Key == "":
			keep(e, "not to go now")
			continue
		case planned.Size != e.Size || planned.ETag != e.ETag:
			keep(e, "not as planned in the index")
			continue
		}
		if time.Since(checked[p.bucket]) > 30*time.Second { // a BOM or manifest new since: what it lists stays
			why, err := s.gcChanged(ctx, p)
			if err == nil && why == "" {
				roots[p.bucket], _, err = s.index.Roots(ctx, p.bucket, s.manifestKeys.IDs())
			}
			if err != nil || why != "" {
				fmt.Fprintf(out, "volume %q: stopped: %s\n", p.Volume, cmp.Or(why, fmt.Sprint(err)))
				p.Refused = cmp.Or(why, "an error")
				if err != nil {
					code = 1
				} else if code == 0 {
					code = 2
				}
				keep(e, "its volume stopped")
				continue
			}
			checked[p.bucket] = time.Now()
		}
		if roots[p.bucket][strings.ToLower(path.Base(path.Dir(e.Key)))] {
			keep(e, "a manifest lists it now")
			continue
		}
		if row, ok, err := s.index.Get(ctx, p.bucket, e.Key); err != nil {
			keep(e, "the index: "+err.Error())
			code = 1
			continue
		} else if ok && (row.Reads != e.Reads || !row.ReadAt.Equal(e.ReadAt)) {
			keep(e, "read since planned")
			continue
		}
		st := s.stores[p.Volume]
		octx, cancel := context.WithTimeout(ctx, time.Minute)
		fi, found, err := st.Stat(octx, e.Key)
		if err == nil && found && fi.Size == e.Size && fi.ETag == e.ETag {
			err = st.Remove(octx, e.Key)
		}
		cancel()
		switch {
		case err != nil:
			keep(e, "not deleted: "+err.Error())
			failed++
			code = 1
		case !found:
			keep(e, "gone already")
			failed = 0
		case fi.Size != e.Size || fi.ETag != e.ETag:
			keep(e, "changed in the bucket since planned")
			failed = 0
		default:
			fmt.Fprintf(out, "deleted: %s %s %s\n", e.Volume, e.Key, bytesOf(e.Size))
			deleted, freed = deleted+1, freed+e.Size
			failed = 0
		}
		if failed >= 10 {
			fmt.Fprintln(out, "stopped: 10 files in a row not deleted")
			break
		}
	}
	fmt.Fprintf(out, "%d deleted (%s), %d kept, of the %d in %s (planned %s)\n", deleted, bytesOf(freed),
		kept, len(f.Files), name, f.Planned.Format(time.RFC3339))
	return code
}

// gcChanged says why the plan's bucket may no longer be swept now ("" when it may):
// manifests not all read (a BOM new since the plan, say).
func (s *Server) gcChanged(ctx context.Context, p *GCPlan) (string, error) {
	if n, err := s.index.Unread(ctx, p.bucket); err != nil || n > 0 {
		return fmt.Sprintf("%d manifests could not be read", n), err
	}
	for _, m := range p.mans {
		todo, err := s.index.ManifestsToRead(ctx, p.bucket, m, s.manifestKeys.IDs(), s.now(), 1)
		if err != nil || len(todo) > 0 {
			return "manifests new since the plan, not all read yet", err
		}
	}
	return "", nil
}

// writePlan writes plans for people: 0 when every volume may be swept, else 2.
func writePlan(out io.Writer, plans []*GCPlan, o GCOptions) int {
	if len(plans) == 0 {
		fmt.Fprintln(out, "no volume with keys holds packages (a tarballs binding): nothing to plan")
	}
	code := 0
	for _, p := range plans {
		if p.Refused != "" {
			fmt.Fprintf(out, "volume %q: nothing may go: %s\n", p.Volume, p.Refused)
			code = 2
		}
		for _, a := range p.Arches {
			if !a.Certified {
				fmt.Fprintf(out, "volume %q: %s: not certified, all %d kept\n", p.Volume, a.Arch, a.Kept+a.Other)
				continue
			}
			newest := ""
			if o.KeepBuilds > 0 {
				newest = fmt.Sprintf(", %d of the %d newest builds of their version", a.Newest, o.KeepBuilds)
			}
			fmt.Fprintf(out, "volume %q: %s: %d kept (%s), %d younger than %s, %d read lately%s, %d not packages; %d would go (%s)\n",
				p.Volume, a.Arch, a.Kept, bytesOf(a.KeptBytes), a.Young, o.Grace, a.Read, newest, a.Other, a.Sweep, bytesOf(a.SweepBytes))
		}
		verb := "would go"
		if p.Refused != "" {
			verb = "would go once allowed"
		}
		for _, a := range p.Arches {
			if !o.List {
				break
			}
			for _, f := range a.sweep {
				last := "never read"
				if !f.ReadAt.IsZero() {
					last = "last read " + f.ReadAt.UTC().Format(time.DateOnly)
				}
				fmt.Fprintf(out, "%s: %s %s, written %s, %d reads, %s\n", verb, f.Key, bytesOf(f.Size),
					f.Mtime.UTC().Format(time.DateOnly), f.Reads, last)
			}
		}
	}
	fmt.Fprintln(out, "a plan: nothing was deleted")
	return code
}

func bytesOf(n int64) string {
	f, unit := float64(n), 0
	for f >= 1024 && unit < 4 {
		f, unit = f/1024, unit+1
	}
	return fmt.Sprintf("%.1f %s", f, []string{"B", "KiB", "MiB", "GiB", "TiB"}[unit])
}

// strayRoots adds to roots what the bucket's common manifests outside its manifests
// bindings list (the orchestrator's CANARY/ ones, say), read now: "" when it did,
// else why a collection may not go on.
func (s *Server) strayRoots(ctx context.Context, bucket, volume string, roots map[string]bool) (string, error) {
	strays, err := s.index.Strays(ctx, bucket)
	if err != nil {
		return "", err
	}
	known, folders := map[string]bool{}, map[string]bool{}
	for _, k := range strays {
		known[k] = true
		folders[strings.TrimSuffix(k, path.Base(k))] = true
	}
	for f := range folders { // their folders now: none new since the listing
		names, err := s.stores[volume].List(ctx, f+"common-manifest-")
		if err != nil {
			return fmt.Sprintf("%s could not be listed: %v", f, err), nil
		}
		for _, n := range names {
			if strings.HasSuffix(n, ".json") && !known[n] {
				return n + " is new since the last listing", nil
			}
		}
	}
	for _, k := range strays {
		body, ok, err := s.stores[volume].Get(ctx, k, maxManifest)
		if err != nil || !ok {
			return fmt.Sprintf("%s could not be read: %v", k, cmp.Or(err, errGone)), nil
		}
		m := index.Parse(k, "", body)
		if m.Kind != index.KindCommon || m.Skipped > 0 {
			return k + " is not a common manifest, or not all of its packages could be read", nil
		}
		for _, e := range m.Entries {
			roots[e.Hash] = true
		}
	}
	return "", nil
}

// A package file's name as bits writes it: <package>-<version>-<revision>.<arch>.tar.gz,
// the revision a number or local<number> (where package and version split does not matter).
var packageName = regexp.MustCompile(`^(.+)-(?:local)?[0-9]+$`)

// versionOf is a package file's architecture and its name without the revision,
// "" when the name is not as bits writes it.
func versionOf(arch string, m []string) string {
	file := m[0][strings.LastIndex(m[0], "/")+1:]
	stem, ok := strings.CutSuffix(file, "."+arch+".tar.gz")
	n := packageName.FindStringSubmatch(stem)
	if !ok || n == nil {
		return ""
	}
	return arch + "/" + n[1]
}

// newestBuilds is the keys of the n newest files (by write time) of each version.
func newestBuilds(builds map[string][]index.Object, n int) map[string]bool {
	out := map[string]bool{}
	for _, fs := range builds {
		slices.SortFunc(fs, func(a, b index.Object) int {
			return cmp.Or(b.Mtime.Compare(a.Mtime), strings.Compare(b.Key, a.Key))
		})
		for _, f := range fs[:min(n, len(fs))] {
			out[f.Key] = true
		}
	}
	return out
}
