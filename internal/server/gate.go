// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"slices"

	"github.com/bitsorg/bits-store/internal/token"
)

// admits says whether t may read key behind b's gate: its group wrote the object,
// or is among the binding's readers of that group. A writer not known: no one.
func (s *Server) admits(ctx context.Context, b *Binding, t *token.Token, key string) (bool, error) {
	if s.index == nil || t == nil || t.Grp == "" {
		return false, nil
	}
	at := s.place[b.Volume]
	o, ok, err := s.index.Get(ctx, at, key)
	if err != nil {
		return false, err
	}
	if !ok || o.Grp == "" { // not listed yet, or its writer not known: the object says
		fi, found, err := s.stores[b.Volume].Stat(ctx, key)
		if err != nil || !found {
			return false, err
		}
		if o.Grp = writer(fi); ok && o.Grp != "" {
			s.index.SetWriter(ctx, at, key, fi.ETag, o.Grp) // its error counted; read again next time
		}
	}
	return o.Grp == t.Grp || slices.Contains(b.Readers[o.Grp], t.Grp), nil
}
