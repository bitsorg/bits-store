// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"time"
)

// FillsKept is how long a day's fetches from upstream stay counted.
const FillsKept = 400 * 24 * time.Hour

// Fill is what fetches from one upstream host came to, in one format: on one day
// (AddFills), or summed over days (Fills).
type Fill struct {
	Day     string `json:"-"` // YYYY-MM-DD, UTC
	Format  string `json:"format"`
	Host    string `json:"host"`
	OK      int64  `json:"ok"`
	Failed  int64  `json:"failed"`
	Refused int64  `json:"refused"` // not started: no room, or the host's budget spent
	Bytes   int64  `json:"bytes"`
}

// AddFills adds fs to their days' counts; days older than FillsKept are deleted.
func (x *Index) AddFills(ctx context.Context, fs []Fill, now time.Time) error {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		x.errors.Add(1)
		return err
	}
	defer tx.Rollback()
	for _, f := range fs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO fills (day, format, host, ok, failed, refused, bytes)
			VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (day, format, host) DO UPDATE SET ok = ok + excluded.ok,
			failed = failed + excluded.failed, refused = refused + excluded.refused, bytes = bytes + excluded.bytes`,
			f.Day, f.Format, f.Host, f.OK, f.Failed, f.Refused, f.Bytes); err != nil {
			x.errors.Add(1)
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fills WHERE day < ?`,
		now.UTC().Add(-FillsKept).Format(time.DateOnly)); err != nil {
		x.errors.Add(1)
		return err
	}
	if err := tx.Commit(); err != nil {
		x.errors.Add(1)
		return err
	}
	return nil
}

// Fills is the fetches since a day (YYYY-MM-DD, UTC), summed by format and host, the
// most first.
func (x *Index) Fills(ctx context.Context, since string) ([]Fill, error) {
	rows, err := x.db.QueryContext(ctx, `SELECT format, host, sum(ok), sum(failed), sum(refused), sum(bytes)
		FROM fills WHERE day >= ? GROUP BY format, host
		ORDER BY sum(ok) + sum(failed) + sum(refused) DESC, format, host`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Fill{}
	for rows.Next() {
		var f Fill
		if err := rows.Scan(&f.Format, &f.Host, &f.OK, &f.Failed, &f.Refused, &f.Bytes); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
