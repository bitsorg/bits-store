// SPDX-License-Identifier: Apache-2.0

// Package index is the store's index: what each bucket holds, kept by the
// service's own writes and checked against a listing of the bucket (Verify).
// It is a cache: the buckets are the truth, and a listing rebuilds it, except
// each object's writer (its metadata, not in a listing).
package index

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
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
	Reads  int64     // GETs the service redirected to it (not reads straight from the bucket)
	ReadAt time.Time // the last of them; zero: none
	Grp    string    // the group whose token wrote it through the service; "": not known
}

// Drift is what a verify found the index to differ in from the bucket.
type Drift struct {
	Missing, Changed, Extra int64 // listed, not indexed; listed otherwise; indexed, not listed
}

// Index is safe for concurrent use: one connection, so its writes never wait on a lock.
type Index struct {
	db       *sql.DB
	errors   atomic.Int64
	readOnly bool // OpenReadOnly's
}

// schemaVersion is the tables' layout: a file of another is migrated or dropped (migrate).
const schemaVersion = 6

const schema = `
CREATE TABLE IF NOT EXISTS objects (
  bucket  TEXT NOT NULL,     -- the volume's endpoint and bucket: names may change
  key     TEXT NOT NULL,
  size    INTEGER NOT NULL,
  etag    TEXT NOT NULL,
  mtime   INTEGER NOT NULL,  -- ms
  sha256  TEXT,
  seen    INTEGER NOT NULL,  -- ms: written by us, or the start of the listing that saw it
  reads   INTEGER NOT NULL DEFAULT 0,  -- GETs redirected to it by the service
  read_at INTEGER NOT NULL DEFAULT 0,  -- ms, the last of them
  grp     TEXT NOT NULL DEFAULT '',    -- the group that wrote it through the service ('' not known)
  PRIMARY KEY (bucket, key)) WITHOUT ROWID;  -- a range of keys reads its rows in place
CREATE TABLE IF NOT EXISTS verified (
  bucket  TEXT PRIMARY KEY,
  at      INTEGER NOT NULL,  -- ms, the start of the listing
  missing INTEGER NOT NULL, changed INTEGER NOT NULL, extra INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS manifests (
  bucket  TEXT NOT NULL,
  key     TEXT NOT NULL,
  etag    TEXT NOT NULL,     -- of the object read: read again when it changes
  kind    TEXT NOT NULL,     -- bom, common, none (not a manifest), or unread
  read_at INTEGER NOT NULL,  -- ms
  sig_etag TEXT NOT NULL,    -- a common manifest's: of its .sig when read ('' none)
  keys    TEXT NOT NULL,     -- the manifest keys it was checked with
  verified_by TEXT NOT NULL, -- the key that verifies its .sig ('' none)
  skipped INTEGER NOT NULL,  -- packages not read: no hash as a string
  PRIMARY KEY (bucket, key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS manifest_builds (  -- a BOM's build; a common manifest's sources
  bucket  TEXT NOT NULL, key TEXT NOT NULL, build_id TEXT NOT NULL,
  PRIMARY KEY (bucket, key, build_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS manifest_entries (
  bucket  TEXT NOT NULL, key TEXT NOT NULL, arch TEXT NOT NULL, hash TEXT NOT NULL,
  package TEXT NOT NULL, version TEXT NOT NULL,
  PRIMARY KEY (bucket, key, arch, hash)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS manifest_entries_by_hash ON manifest_entries (bucket, arch, hash);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS problems (  -- the service's warnings and errors (problems.go)
  id      INTEGER PRIMARY KEY,
  first   INTEGER NOT NULL, last INTEGER NOT NULL,  -- ms
  count   INTEGER NOT NULL,
  level   TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS problems_by_kind ON problems (kind, subject, last);
CREATE INDEX IF NOT EXISTS problems_by_last ON problems (last, id);`

var tables = []string{"objects", "verified", "manifests", "manifest_builds", "manifest_entries", "meta", "problems"}

// Open opens (or creates) the index file at path.
func Open(path string) (*Index, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("index %s: %v", path, err)
	}
	return &Index{db: db}, nil
}

// OpenReadOnly opens the index file at path for reading only, as another process
// (bits-store -gc) does beside the service: never created, migrated or written.
func OpenReadOnly(path string) (*Index, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("index %s: %v", path, err)
	}
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+
		"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != schemaVersion {
		db.Close()
		return nil, fmt.Errorf("index %s: layout %d, not this release's %d (%v): run the service first", path, v, schemaVersion, err)
	}
	return &Index{db: db, readOnly: true}, nil
}

// migrate makes the file's tables those of schemaVersion, in one transaction: a
// layout 4 or 5 gains the columns added since; another is dropped (refilled by a listing).
func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var v int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	// the columns each layout added to objects: an older file gains them, kept
	added := map[int][][2]string{5: {{"reads", "INTEGER NOT NULL DEFAULT 0"}, {"read_at", "INTEGER NOT NULL DEFAULT 0"}},
		6: {{"grp", "TEXT NOT NULL DEFAULT ''"}}}
	for v >= 4 && v < schemaVersion {
		v++
		for _, c := range added[v] {
			var n int
			if err := tx.QueryRow(`SELECT count(*) FROM pragma_table_info('objects') WHERE name = ?`, c[0]).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				continue
			}
			if _, err := tx.Exec("ALTER TABLE objects ADD COLUMN " + c[0] + " " + c[1]); err != nil {
				return err
			}
		}
	}
	if v != schemaVersion {
		for _, t := range tables {
			if _, err := tx.Exec("DROP TABLE IF EXISTS " + t); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(schema); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO meta (key, value) VALUES ('reads_since', ?)`,
		strconv.FormatInt(time.Now().UnixMilli(), 10)); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// ReadsSince is when the index began counting reads: none before it are known.
func (x *Index) ReadsSince(ctx context.Context) (time.Time, error) {
	var v string
	if err := x.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'reads_since'`).Scan(&v); err != nil {
		return time.Time{}, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return time.UnixMilli(n), err
}

func (x *Index) Close() error { return x.db.Close() }

// Errors is how many writes of the service failed to reach the index.
func (x *Index) Errors() int64 { return x.errors.Load() }

func ms(t time.Time) int64 { return t.UnixMilli() }

// Put records an object the service wrote, at now; an error is counted too.
func (x *Index) Put(ctx context.Context, bucket string, o Object, now time.Time) error {
	_, err := x.db.ExecContext(ctx, `INSERT INTO objects (bucket, key, size, etag, mtime, sha256, seen, grp)
		VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?) ON CONFLICT (bucket, key) DO UPDATE SET size = excluded.size,
		etag = excluded.etag, mtime = excluded.mtime, sha256 = excluded.sha256, seen = excluded.seen,
		grp = excluded.grp`,
		bucket, o.Key, o.Size, o.ETag, ms(o.Mtime), o.SHA256, ms(now), o.Grp)
	if err != nil {
		x.errors.Add(1)
	}
	return err
}

// Forget drops the bucket's row of a key the service deleted, as it was (its ETag);
// read only (-gc's), it leaves that to the service's next listing.
func (x *Index) Forget(ctx context.Context, bucket, key, etag string) error {
	if x.readOnly {
		return nil
	}
	_, err := x.db.ExecContext(ctx, `DELETE FROM objects WHERE bucket = ? AND key = ? AND etag = ?`, bucket, key, etag)
	return err
}

// Get returns the bucket's row of a key; ok is false when there is none.
func (x *Index) Get(ctx context.Context, bucket, key string) (o Object, ok bool, err error) {
	var mtime int64
	var sha sql.NullString
	var readAt int64
	err = x.db.QueryRowContext(ctx, `SELECT size, etag, mtime, sha256, grp, reads, read_at FROM objects
		WHERE bucket = ? AND key = ?`, bucket, key).Scan(&o.Size, &o.ETag, &mtime, &sha, &o.Grp, &o.Reads, &readAt)
	if err == sql.ErrNoRows {
		return Object{}, false, nil
	}
	o.Key, o.Mtime, o.SHA256 = key, time.UnixMilli(mtime), sha.String
	if readAt > 0 {
		o.ReadAt = time.UnixMilli(readAt)
	}
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

// Under is a bucket's objects under prefix (a folder without its "/"; "": the bucket).
func (x *Index) Under(ctx context.Context, bucket, prefix string) (c Count, err error) {
	if prefix == "" {
		return x.Total(ctx, bucket)
	}
	err = x.db.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(size), 0) FROM objects
		WHERE bucket = ? AND key >= ? AND key < ?`, bucket, prefix+"/", prefix+"0").Scan(&c.Objects, &c.Bytes)
	return c, err
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
				_, err = tx.ExecContext(ctx, `UPDATE objects SET size = ?, etag = ?, mtime = ?, sha256 = NULL, grp = '',
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

// Read is the GETs of an object since the last AddReads, and the last of them.
type Read struct {
	N    int64
	Last time.Time
}

// AddReads adds reads to the objects' counts, by bucket and key; objects not in
// the index (not listed yet) lose theirs.
func (x *Index) AddReads(ctx context.Context, reads map[[2]string]Read) error {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		x.errors.Add(1)
		return err
	}
	defer tx.Rollback()
	for k, r := range reads {
		if _, err := tx.ExecContext(ctx, `UPDATE objects SET reads = reads + ?, read_at = max(read_at, ?)
			WHERE bucket = ? AND key = ?`, r.N, ms(r.Last), k[0], k[1]); err != nil {
			x.errors.Add(1)
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		x.errors.Add(1)
		return err
	}
	return nil
}

// SetReadsSince sets when the index began counting reads (Open sets it to now
// for a new file): for a restored index, or a test.
func (x *Index) SetReadsSince(ctx context.Context, t time.Time) error {
	_, err := x.db.ExecContext(ctx, `UPDATE meta SET value = ? WHERE key = 'reads_since'`,
		strconv.FormatInt(t.UnixMilli(), 10))
	return err
}
