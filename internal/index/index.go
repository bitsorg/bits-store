// SPDX-License-Identifier: Apache-2.0

// Package index is the store's index: what each bucket holds, kept by the
// service's own writes and checked against a listing of the bucket (Verify).
// It is a cache: the buckets are the truth, and a listing rebuilds it.
package index

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure Go, no cgo
)

// Object is one object of a bucket; SHA256 is empty when not known (a listing).
type Object struct {
	Key    string
	Size   int64
	ETag   string
	Mtime  time.Time
	SHA256 string
}

// Drift is what a verify found the index to differ in from the bucket.
type Drift struct {
	Missing, Changed, Extra int64 // listed, not indexed; listed otherwise; indexed, not listed
}

// Index is safe for concurrent use: one connection, so its writes never wait on a lock.
type Index struct {
	db     *sql.DB
	errors atomic.Int64
}

const schema = `
CREATE TABLE IF NOT EXISTS objects (
  bucket  TEXT NOT NULL,     -- the volume's endpoint and bucket: names may change
  key     TEXT NOT NULL,
  size    INTEGER NOT NULL,
  etag    TEXT NOT NULL,
  mtime   INTEGER NOT NULL,  -- ms
  sha256  TEXT,
  seen    INTEGER NOT NULL,  -- ms: written by us, or the start of the listing that saw it
  PRIMARY KEY (bucket, key)) WITHOUT ROWID;  -- a range of keys reads its rows in place
CREATE TABLE IF NOT EXISTS verified (
  bucket  TEXT PRIMARY KEY,
  at      INTEGER NOT NULL,  -- ms, the start of the listing
  missing INTEGER NOT NULL, changed INTEGER NOT NULL, extra INTEGER NOT NULL);`

// Open opens (or creates) the index file at path.
func Open(path string) (*Index, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("index %s: %v", path, err)
	}
	return &Index{db: db}, nil
}

func (x *Index) Close() error { return x.db.Close() }

// Errors is how many writes of the service failed to reach the index.
func (x *Index) Errors() int64 { return x.errors.Load() }

func ms(t time.Time) int64 { return t.UnixMilli() }

// Put records an object the service wrote, at now; an error is counted too.
func (x *Index) Put(ctx context.Context, bucket string, o Object, now time.Time) error {
	_, err := x.db.ExecContext(ctx, `INSERT INTO objects (bucket, key, size, etag, mtime, sha256, seen)
		VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?) ON CONFLICT (bucket, key) DO UPDATE SET size = excluded.size,
		etag = excluded.etag, mtime = excluded.mtime, sha256 = excluded.sha256, seen = excluded.seen`,
		bucket, o.Key, o.Size, o.ETag, ms(o.Mtime), o.SHA256, ms(now))
	if err != nil {
		x.errors.Add(1)
	}
	return err
}

// Get returns the bucket's row of a key; ok is false when there is none.
func (x *Index) Get(ctx context.Context, bucket, key string) (o Object, ok bool, err error) {
	var mtime int64
	var sha sql.NullString
	err = x.db.QueryRowContext(ctx, `SELECT size, etag, mtime, sha256 FROM objects WHERE bucket = ? AND key = ?`,
		bucket, key).Scan(&o.Size, &o.ETag, &mtime, &sha)
	if err == sql.ErrNoRows {
		return Object{}, false, nil
	}
	o.Key, o.Mtime, o.SHA256 = key, time.UnixMilli(mtime), sha.String
	return o, err == nil, err
}

// Count is a number of objects and their bytes.
type Count struct{ Objects, Bytes int64 }

// Total is all of a bucket's objects.
func (x *Index) Total(ctx context.Context, bucket string) (c Count, err error) {
	err = x.db.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(size), 0) FROM objects WHERE bucket = ?`,
		bucket).Scan(&c.Objects, &c.Bytes)
	return c, err
}

// Under groups a bucket's objects under prefix (a folder without its "/"; "": the
// bucket) by the next segment of their keys: under a tarballs prefix, the architecture.
func (x *Index) Under(ctx context.Context, bucket, prefix string) (map[string]Count, error) {
	q, args := "bucket = ?", []any{1, bucket}
	if prefix != "" { // the folder's keys: '0' follows '/'
		q, args = "bucket = ? AND key >= ? AND key < ?", []any{len(prefix) + 2, bucket, prefix + "/", prefix + "0"}
	}
	rows, err := x.db.QueryContext(ctx, `SELECT seg, count(*), sum(size) FROM (
		SELECT CASE instr(rest, '/') WHEN 0 THEN rest ELSE substr(rest, 1, instr(rest, '/') - 1) END AS seg, size
		FROM (SELECT substr(key, ?) AS rest, size FROM objects WHERE `+q+`))
		WHERE seg != '' GROUP BY seg`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Count{}
	for rows.Next() {
		var seg string
		var c Count
		if err := rows.Scan(&seg, &c.Objects, &c.Bytes); err != nil {
			return nil, err
		}
		out[seg] = c
	}
	return out, rows.Err()
}

// Verified returns when the bucket was last verified, and what was found; ok
// is false when it never was.
func (x *Index) Verified(ctx context.Context, bucket string) (at time.Time, d Drift, ok bool, err error) {
	var atMs int64
	err = x.db.QueryRowContext(ctx, `SELECT at, missing, changed, extra FROM verified WHERE bucket = ?`,
		bucket).Scan(&atMs, &d.Missing, &d.Changed, &d.Extra)
	if err == sql.ErrNoRows {
		return time.Time{}, Drift{}, false, nil
	}
	return time.UnixMilli(atMs), d, err == nil, err
}

const batch = 1000 // objects per transaction: the service's writes wait at most one

// Verify makes the bucket's rows those of a listing begun at start: list calls
// its function for each object, in any order, and stops when it returns an error.
// Rows written since start are the service's, newer: kept as they are. Rows not
// listed go. A failed listing removes nothing. Put's now must not precede start.
func (x *Index) Verify(ctx context.Context, bucket string, start time.Time,
	list func(func(Object) error) error) (Drift, error) {
	var d Drift
	pending := make([]Object, 0, batch)
	flush := func() error {
		tx, err := x.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, o := range pending {
			var size, seen int64
			var etag string
			err := tx.QueryRowContext(ctx, `SELECT size, etag, seen FROM objects WHERE bucket = ? AND key = ?`,
				bucket, o.Key).Scan(&size, &etag, &seen)
			switch {
			case err == nil && seen >= ms(start):
				continue // written by the service during this listing
			case err == sql.ErrNoRows:
				d.Missing++
				_, err = tx.ExecContext(ctx, `INSERT INTO objects (bucket, key, size, etag, mtime, seen)
					VALUES (?, ?, ?, ?, ?, ?)`, bucket, o.Key, o.Size, o.ETag, ms(o.Mtime), ms(start))
			case err != nil:
			case size != o.Size || etag != o.ETag:
				d.Changed++ // the sha256 we recorded is no longer this object's
				_, err = tx.ExecContext(ctx, `UPDATE objects SET size = ?, etag = ?, mtime = ?, sha256 = NULL,
					seen = ? WHERE bucket = ? AND key = ?`, o.Size, o.ETag, ms(o.Mtime), ms(start), bucket, o.Key)
			default:
				_, err = tx.ExecContext(ctx, `UPDATE objects SET seen = ? WHERE bucket = ? AND key = ?`,
					ms(start), bucket, o.Key)
			}
			if err != nil {
				return err
			}
		}
		pending = pending[:0]
		return tx.Commit()
	}
	err := list(func(o Object) error {
		if pending = append(pending, o); len(pending) == batch {
			return flush()
		}
		return nil
	})
	if err == nil && len(pending) > 0 {
		err = flush()
	}
	if err != nil {
		return d, err // what was upserted stays: it was listed
	}
	r, err := x.db.ExecContext(ctx, `DELETE FROM objects WHERE bucket = ? AND seen < ?`, bucket, ms(start))
	if err != nil {
		return d, err
	}
	d.Extra, _ = r.RowsAffected()
	_, err = x.db.ExecContext(ctx, `INSERT INTO verified (bucket, at, missing, changed, extra) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (bucket) DO UPDATE SET at = excluded.at, missing = excluded.missing,
		changed = excluded.changed, extra = excluded.extra`, bucket, ms(start), d.Missing, d.Changed, d.Extra)
	return d, err
}
