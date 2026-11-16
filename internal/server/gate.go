// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"maps"
	"path"
	"regexp"
	"slices"
	"time"

	"github.com/bitsorg/bits-store/internal/token"
)

// groupName is a group a gated binding files builds under (as the broker names them).
var groupName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// within is b as group g has it behind a gate: its key prefix and dir under g's folder.
func within(b *Binding, g, dir string) (*Binding, string) {
	gb := *b
	gb.KeyPrefix = path.Join(b.KeyPrefix, g)
	return &gb, gb.KeyPrefix + "/" + b.unprefixed(dir)
}

// readable are the groups whose builds t reads behind b's gate: its own, then
// those that list it among their readers.
func readable(b *Binding, t *token.Token) []string {
	if t == nil || !groupName.MatchString(t.Grp) {
		return nil
	}
	out := []string{t.Grp}
	for _, g := range slices.Sorted(maps.Keys(b.Readers)) {
		if g != t.Grp && slices.Contains(b.Readers[g], t.Grp) {
			out = append(out, g)
		}
	}
	return out
}

// gatedLookup finds the build in dir among the groups t reads, in that order: the
// binding as that group has it, and the object; "" when none has it.
func (s *Server) gatedLookup(ctx context.Context, b *Binding, t *token.Token, dir string, now time.Time) (*Binding, string, error) {
	for _, g := range readable(b, t) {
		gb, gdir := within(b, g, dir)
		if key, err := s.found.lookup(ctx, s, gb, gdir, now); err != nil || key != "" {
			return gb, key, err
		}
	}
	return b, "", nil
}

// grouped says whether a tarballs prefix of the bucket at is a gated binding's,
// its builds a folder deeper (one per group).
func (s *Server) grouped(at, prefix string) bool {
	for _, b := range s.bindings {
		if b.Gate != "" && s.place[b.Volume] == at && path.Clean("/"+b.KeyPrefix) == path.Clean("/"+prefix) {
			return true
		}
	}
	return false
}
