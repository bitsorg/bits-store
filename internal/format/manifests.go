// SPDX-License-Identifier: Apache-2.0

package format

import (
	"errors"
	"strings"
)

// Manifests is bits' MANIFESTS area: the path under the prefix is the key, as blob,
// and rev-index/<arch>/<pkg>/<version>?revisions answers the revision markers of
// that version (rev-index/<arch>/<pkg>/<version>-<revision>, each holding a hash).
type Manifests struct{}

func (Manifests) Name() string { return "manifests" }

func (Manifests) Route(rest []string) (Item, error) {
	if len(rest) == 0 {
		return Item{}, errors.New("no object named")
	}
	return Item{Key: strings.Join(rest, "/")}, nil
}

func (Manifests) RevisionsOf(rest []string) error {
	if len(rest) != 4 || rest[0] != "rev-index" {
		return errors.New("not rev-index/<arch>/<pkg>/<version>")
	}
	return nil
}

func init() { Register(Manifests{}) }
