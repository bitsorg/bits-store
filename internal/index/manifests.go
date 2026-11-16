// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"database/sql"
	"encoding/json"
	"path"
	"strings"
	"time"
)

// Kinds of manifest: a build's BOM, a (signed) common manifest, or neither.
const (
	KindBOM    = "bom"
	KindCommon = "common"
	KindNone   = "none"
	KindUnread = "unread" // reading it failed: tried again after RetryUnread
)

// RetryUnread is how long a file whose reading failed waits for the next try.
const RetryUnread = time.Hour

// Entry is an object a manifest lists: a build of a package, by architecture and hash.
type Entry struct {
	Arch, Hash, Package, Version string
}

// Manifest is what the index keeps of a file under a manifests binding.
type Manifest struct {
	Key, ETag, Kind string
	At              time.Time // when read
	Builds          []string  // a BOM's build; a common manifest's sources
	Entries         []Entry
}

// Parse reads a file under a manifests binding (key relative to the bucket): a
// common manifest by its name and kind, else a BOM by its build id and packages;
// anything else is KindNone. Packages and sources not as expected are skipped.
func Parse(key, etag string, body []byte) Manifest {
	m := Manifest{Key: key, ETag: etag, Kind: KindNone}
	var doc struct {
		Kind     string            `json:"kind"`
		BuildID  string            `json:"build_id"`
		Arch     string            `json:"effective_architecture"`
		Sources  []any             `json:"sources"`
		Packages []json.RawMessage `json:"packages"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.Packages == nil {
		return m
	}
	switch {
	case strings.HasPrefix(path.Base(key), "common-manifest-") && doc.Kind == "common-manifest":
		m.Kind = KindCommon
		for _, b := range doc.Sources {
			if b, ok := b.(string); ok && b != "" {
				m.Builds = append(m.Builds, b)
			}
		}
	case doc.BuildID != "":
		m.Kind, m.Builds = KindBOM, []string{doc.BuildID}
	default:
		return m
	}
	seen := map[[2]string]bool{}
	for _, raw := range doc.Packages {
		var p struct {
			Package, Version, Hash string
			Arch                   string `json:"effective_architecture"`
		}
		if json.Unmarshal(raw, &p) != nil || p.Hash == "" {
			continue
		}
		if p.Arch == "" {
			p.Arch = doc.Arch
		}
		if k := [2]string{p.Arch, p.Hash}; !seen[k] {
			seen[k] = true
			m.Entries = append(m.Entries, Entry{Arch: p.Arch, Hash: p.Hash, Package: p.Package, Version: p.Version})
		}
	}
	return m
}

// ManifestsToRead lists the bucket's .json objects under prefix (a folder without
// its "/"; "": the bucket), outside its rev-index/, not read at their present ETag
// (or unread for RetryUnread at now): at most limit.
func (x *Index) ManifestsToRead(ctx context.Context, bucket, prefix string, now time.Time, limit int) ([]Object, error) {
	in, args := "", []any{bucket, "rev-index/", "rev-index0"} // "": the whole bucket
	if prefix != "" {
		in, args = " AND o.key >= ? AND o.key < ?", []any{bucket, prefix + "/rev-index/", prefix + "/rev-index0",
			prefix + "/", prefix + "0"} // the folder's keys: '0' follows '/'
	}
	rows, err := x.db.QueryContext(ctx, `SELECT o.key, o.size, o.etag FROM objects o
		LEFT JOIN manifests m ON m.bucket = o.bucket AND m.key = o.key
		WHERE o.bucket = ? AND NOT (o.key >= ? AND o.key < ?)`+in+`
		AND o.key GLOB '*.json' AND (m.key IS NULL OR m.etag != o.etag OR m.kind = ? AND m.read_at <= ?)
		ORDER BY o.key LIMIT ?`, append(args, KindUnread, ms(now.Add(-RetryUnread)), limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Object
	for rows.Next() {
		var o Object
		if err := rows.Scan(&o.Key, &o.Size, &o.ETag); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// PutManifest replaces what the index has of a manifest's file.
func (x *Index) PutManifest(ctx context.Context, bucket string, m Manifest) error {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := dropManifest(ctx, tx, bucket, m.Key); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO manifests (bucket, key, etag, kind, read_at) VALUES (?, ?, ?, ?, ?)`,
		bucket, m.Key, m.ETag, m.Kind, ms(m.At)); err != nil {
		return err
	}
	for _, b := range m.Builds {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO manifest_builds (bucket, key, build_id)
			VALUES (?, ?, ?)`, bucket, m.Key, b); err != nil {
			return err
		}
	}
	for _, e := range m.Entries {
		if _, err := tx.ExecContext(ctx, `INSERT INTO manifest_entries (bucket, key, arch, hash, package, version)
			VALUES (?, ?, ?, ?, ?, ?)`, bucket, m.Key, e.Arch, e.Hash, e.Package, e.Version); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func dropManifest(ctx context.Context, tx *sql.Tx, bucket, key string) error {
	for _, t := range []string{"manifests", "manifest_builds", "manifest_entries"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE bucket = ? AND key = ?`, bucket, key); err != nil {
			return err
		}
	}
	return nil
}

// DropGoneManifests removes the manifests of objects no longer in the bucket.
func (x *Index) DropGoneManifests(ctx context.Context, bucket string) (int64, error) {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	const gone = `SELECT m.key FROM manifests m WHERE m.bucket = ? AND NOT EXISTS
		(SELECT 1 FROM objects o WHERE o.bucket = m.bucket AND o.key = m.key)`
	for _, t := range []string{"manifest_builds", "manifest_entries"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE bucket = ? AND key IN (`+gone+`)`,
			bucket, bucket); err != nil {
			return 0, err
		}
	}
	r, err := tx.ExecContext(ctx, `DELETE FROM manifests WHERE bucket = ? AND key IN (`+gone+`)`, bucket, bucket)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, tx.Commit()
}

// Builds returns the builds a manifest names and its kind ("" when not indexed).
func (x *Index) Builds(ctx context.Context, bucket, key string) (kind string, builds []string, err error) {
	if err = x.db.QueryRowContext(ctx, `SELECT kind FROM manifests WHERE bucket = ? AND key = ?`,
		bucket, key).Scan(&kind); err == sql.ErrNoRows {
		return "", nil, nil
	} else if err != nil {
		return "", nil, err
	}
	rows, err := x.db.QueryContext(ctx, `SELECT build_id FROM manifest_builds WHERE bucket = ? AND key = ?
		ORDER BY build_id`, bucket, key)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			return "", nil, err
		}
		builds = append(builds, b)
	}
	return kind, builds, rows.Err()
}
