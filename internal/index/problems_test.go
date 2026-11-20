// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"testing"
	"time"
)

// The same problem within an hour adds to its row; another hour, or another
// subject, is a row of its own; a month old is deleted.
func TestProblems(t *testing.T) {
	x, _ := open(t)
	ctx := context.Background()
	t0 := time.UnixMilli(1_800_000_000_000)
	p := func(at time.Time, subject string, n int64) Problem {
		return Problem{First: at, Last: at, Count: n, Level: "error", Kind: "presign_failed", Subject: subject, Message: "presign k: denied"}
	}
	add := func(now time.Time, ps ...Problem) {
		if err := x.AddProblems(ctx, ps, now); err != nil {
			t.Fatal(err)
		}
	}
	add(t0, p(t0, "k", 2), p(t0, "j", 1))
	add(t0.Add(30*time.Minute), p(t0.Add(30*time.Minute), "k", 3))
	add(t0.Add(3*time.Hour), p(t0.Add(3*time.Hour), "k", 1))
	got, err := x.Problems(ctx, 0, 10)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %+v", err, got)
	}
	if k := got[1]; k.Subject != "k" || k.Count != 5 || k.FirstMs != t0.UnixMilli() || k.LastMs != t0.Add(30*time.Minute).UnixMilli() {
		t.Fatalf("not merged within the hour: %+v", got)
	}
	if got[2].Count != 1 || got[0].Subject != "j" {
		t.Fatalf("order, or merged after the hour: %+v", got)
	}
	if since, _ := x.Problems(ctx, t0.Add(time.Hour).UnixMilli(), 10); len(since) != 1 {
		t.Fatalf("since: %+v", since)
	}
	add(t0.Add(ProblemsKept + 2*time.Hour)) // a month on: the first two go
	if left, _ := x.Problems(ctx, 0, 10); len(left) != 1 || left[0].LastMs != t0.Add(3*time.Hour).UnixMilli() {
		t.Fatalf("not deleted: %+v", left)
	}
}
