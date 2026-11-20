// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"
)

// adminFills answers GET /_admin/fills?since=<YYYY-MM-DD>: the fetches from upstream
// since that day (30 days by default), summed by format and host, the most first.
func (s *Server) adminFills(w http.ResponseWriter, rawQuery string) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return failMsg(w, http.StatusBadRequest, "query")
	}
	since := s.now().UTC().AddDate(0, 0, -29).Format(time.DateOnly)
	if v := q.Get("since"); v != "" {
		if _, err := time.Parse(time.DateOnly, v); err != nil {
			return failMsg(w, http.StatusBadRequest, "since")
		}
		since = v
	}
	s.flushFills(context.Background()) // the latest too
	fs, err := s.index.Fills(context.Background(), since)
	if err != nil {
		log.Printf("admin fills: %v", err)
		return fail(w, http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"since": since, "fills": fs})
	return http.StatusOK
}
