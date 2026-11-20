// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/bitsorg/bits-store/internal/index"
	"github.com/bitsorg/bits-store/internal/token"
)

const (
	whereLooks = 2000      // places a request asks about, at most
	whereRows  = 3         // objects answered per place, at most
	whereBody  = 512 << 10 // its JSON
)

// adminWhere answers POST /_admin/where {"look": [{"binding", "under"}, ...]}: for
// each place, in order, the first objects the index has under that folder of the
// binding (as a search shows them), or null for a binding not configured.
func (s *Server) adminWhere(w http.ResponseWriter, r *http.Request) int {
	if s.index == nil {
		return fail(w, http.StatusNotFound)
	}
	var req struct {
		Look []struct {
			Binding string `json:"binding"`
			Under   string `json:"under"`
		} `json:"look"`
	}
	if !readJSONUpTo(w, r, &req, whereBody) {
		return failMsg(w, http.StatusBadRequest, "body")
	}
	if len(req.Look) > whereLooks {
		return failMsg(w, http.StatusBadRequest, "look: too many")
	}
	found := make([][]ObjectRow, len(req.Look))
	for i, l := range req.Look {
		b := s.binding(l.Binding)
		if b == nil {
			continue
		}
		under := strings.TrimSuffix(l.Under, "/")
		if _, err := token.ParsePath("/" + under); err != nil || under == "" {
			return failMsg(w, http.StatusBadRequest, "under")
		}
		prefix := strings.TrimPrefix(strings.TrimSuffix(b.KeyPrefix, "/")+"/"+under, "/")
		rows := []ObjectRow{}
		err := s.index.Search(r.Context(), s.place[b.Volume], prefix, "", "", whereRows, func(o index.Object, _ string) bool {
			rows = append(rows, objectRow(b, o, ""))
			return true
		})
		if err != nil {
			log.Printf("admin where: %v", err)
			return fail(w, http.StatusInternalServerError)
		}
		found[i] = rows
	}
	return writeJSON(w, map[string]any{"found": found})
}
