// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// A day's fetches add up by format and host; days past FillsKept go.
func TestFills(t *testing.T) {
	x, err := Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	ctx, now := context.Background(), time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	old := now.Add(-FillsKept - 24*time.Hour).Format(time.DateOnly)
	for _, fs := range [][]Fill{
		{{Day: "2026-11-19", Format: "sources", Host: "ftp.gnu.org", OK: 1, Bytes: 10},
			{Day: "2026-11-20", Format: "sources", Host: "ftp.gnu.org", Failed: 2},
			{Day: old, Format: "sources", Host: "gone.example.org", OK: 9}},
		{{Day: "2026-11-20", Format: "sources", Host: "ftp.gnu.org", OK: 3, Refused: 1, Bytes: 30},
			{Day: "2026-11-20", Format: "pypi", Host: "files.pythonhosted.org", OK: 1}},
	} {
		if err := x.AddFills(ctx, fs, now); err != nil {
			t.Fatal(err)
		}
	}
	got, err := x.Fills(ctx, "2000-01-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (Fill{Format: "sources", Host: "ftp.gnu.org", OK: 4, Failed: 2, Refused: 1, Bytes: 40}) ||
		got[1].Host != "files.pythonhosted.org" {
		t.Fatalf("all days: %+v", got)
	}
	if got, _ := x.Fills(ctx, "2026-11-20"); len(got) != 2 || got[0].OK != 3 || got[0].Failed != 2 || got[0].Bytes != 30 {
		t.Fatalf("since a day: %+v", got)
	}
}
