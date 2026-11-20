// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"time"
)

const (
	ProblemsKept  = 30 * 24 * time.Hour // older problems are deleted
	problemsMerge = time.Hour           // the same problem again within it counts on the same row
)

// Problem is a warning or an error of the service: the same one (level, kind,
// subject, message) seen Count times between First and Last.
type Problem struct {
	ID          int64     `json:"id"`
	First, Last time.Time `json:"-"`
	FirstMs     int64     `json:"first"` // ms, as Last
	LastMs      int64     `json:"last"`
	Count       int64     `json:"count"`
	Level       string    `json:"level"` // warning, error
	Kind        string    `json:"kind"`
	Subject     string    `json:"subject"`
	Message     string    `json:"message"`
}

// AddProblems records problems: one seen within problemsMerge of the same one adds
// to its row. Those older than ProblemsKept are deleted.
func (x *Index) AddProblems(ctx context.Context, ps []Problem, now time.Time) error {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		x.errors.Add(1)
		return err
	}
	defer tx.Rollback()
	for _, p := range ps {
		r, err := tx.ExecContext(ctx, `UPDATE problems SET count = count + ?, last = max(last, ?)
			WHERE kind = ? AND subject = ? AND level = ? AND message = ? AND last >= ?`,
			p.Count, ms(p.Last), p.Kind, p.Subject, p.Level, p.Message, ms(p.First.Add(-problemsMerge)))
		if err != nil {
			x.errors.Add(1)
			return err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO problems (first, last, count, level, kind, subject, message)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, ms(p.First), ms(p.Last), p.Count, p.Level, p.Kind, p.Subject, p.Message); err != nil {
			x.errors.Add(1)
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM problems WHERE last < ?`, ms(now.Add(-ProblemsKept))); err != nil {
		x.errors.Add(1)
		return err
	}
	if err := tx.Commit(); err != nil {
		x.errors.Add(1)
		return err
	}
	return nil
}

// Problems is the problems last seen at or after since (ms), oldest first, at most limit.
func (x *Index) Problems(ctx context.Context, since int64, limit int) ([]Problem, error) {
	rows, err := x.db.QueryContext(ctx, `SELECT id, first, last, count, level, kind, subject, message
		FROM problems WHERE last >= ? ORDER BY last, id LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Problem{}
	for rows.Next() {
		var p Problem
		if err := rows.Scan(&p.ID, &p.FirstMs, &p.LastMs, &p.Count, &p.Level, &p.Kind, &p.Subject, &p.Message); err != nil {
			return nil, err
		}
		p.First, p.Last = time.UnixMilli(p.FirstMs), time.UnixMilli(p.LastMs)
		out = append(out, p)
	}
	return out, rows.Err()
}
