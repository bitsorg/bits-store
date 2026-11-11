// SPDX-License-Identifier: Apache-2.0

package format

import (
	"errors"
	"strings"
)

// Blob is the default format: the path under the prefix is the key, as is.
type Blob struct{}

func (Blob) Name() string { return "blob" }

func (Blob) Route(rest []string) (Item, error) {
	if len(rest) == 0 {
		return Item{}, errors.New("no object named")
	}
	return Item{Key: strings.Join(rest, "/")}, nil
}

func init() { Register(Blob{}) }
