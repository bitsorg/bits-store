// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"strings"
	"time"
)

// Common is an indexed common manifest: its ETag and its .sig's when read, and
// whether it verified with the keys now in force.
type Common struct {
	ETag, SigETag string
	Verified      bool
}

// Commons returns the bucket's common manifests by key; verified with keys (their ids).
func (x *Index) Commons(ctx context.Context, bucket, keys string) (map[string]Common, error) {
	rows, err := x.db.QueryContext(ctx, `SELECT key, etag, sig_etag, keys = ? AND verified_by != ''
		FROM manifests WHERE bucket = ? AND kind = ?`, keys, bucket, KindCommon)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Common{}
	for rows.Next() {
		var k string
		var c Common
		if err := rows.Scan(&k, &c.ETag, &c.SigETag, &c.Verified); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

// Unread is how many of the bucket's manifests could not be read, or were read
// with packages skipped (not objects, or hashes not strings).
func (x *Index) Unread(ctx context.Context, bucket string) (n int, err error) {
	err = x.db.QueryRowContext(ctx, `SELECT count(*) FROM manifests WHERE bucket = ? AND (kind = ? OR skipped > 0)`,
		bucket, KindUnread).Scan(&n)
	return n, err
}

// Strays lists the bucket's common-manifest-*.json objects not read as common
// manifests (outside the manifests bindings, or of another kind): a collection
// reads them itself, for their roots.
func (x *Index) Strays(ctx context.Context, bucket string) ([]string, error) {
	rows, err := x.db.QueryContext(ctx, `SELECT o.key FROM objects o
		LEFT JOIN manifests m ON m.bucket = o.bucket AND m.key = o.key
		WHERE o.bucket = ? AND o.key GLOB '*common-manifest-*.json' AND (m.kind IS NULL OR m.kind != ?)
		ORDER BY o.key`, bucket, KindCommon)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Roots are the hashes a collection keeps: those any common manifest lists, those
// the BOMs of their sources list, and those of BOMs newer than since (builds that
// reused them may be certified soon); and the architectures that common manifests
// verified with keys (their ids) list, the only ones a collection may sweep.
func (x *Index) Roots(ctx context.Context, bucket, keys string, since time.Time) (hashes, certified map[string]bool, err error) {
	hashes, certified = map[string]bool{}, map[string]bool{}
	rows, err := x.db.QueryContext(ctx, `
		SELECT e.hash, m.kind = ? AND ? != '' AND m.keys = ? AND m.verified_by != '', e.arch
		  FROM manifest_entries e JOIN manifests m ON m.bucket = e.bucket AND m.key = e.key
		  WHERE e.bucket = ? AND m.kind = ?
		UNION ALL
		SELECT e.hash, 0, '' FROM manifest_entries e
		  JOIN manifests m ON m.bucket = e.bucket AND m.key = e.key AND m.kind = ?
		  JOIN objects o ON o.bucket = e.bucket AND o.key = e.key
		  WHERE e.bucket = ? AND (o.mtime > ? OR EXISTS (SELECT 1 FROM manifest_builds b
		    JOIN manifest_builds s ON s.bucket = b.bucket AND s.build_id = b.build_id
		    JOIN manifests c ON c.bucket = s.bucket AND c.key = s.key AND c.kind = ?
		    WHERE b.bucket = e.bucket AND b.key = e.key))`,
		KindCommon, keys, keys, bucket, KindCommon, KindBOM, bucket, ms(since), KindCommon)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h, a string
		var verified bool
		if err := rows.Scan(&h, &verified, &a); err != nil {
			return nil, nil, err
		}
		hashes[strings.ToLower(h)] = true
		if verified {
			certified[a] = true
		}
	}
	return hashes, certified, rows.Err()
}
