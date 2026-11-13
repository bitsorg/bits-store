// SPDX-License-Identifier: Apache-2.0

package format

import (
	"errors"
	"regexp"
	"strings"
)

// Tarballs is bits' package store: <arch>/<hash> names the build of that hash, kept
// as <arch>/store/<hash[:2]>/<hash>/<pkg>-<version>[-<revision>].<arch>.tar.gz as
// bits writes it. A read finds it by the hash alone; a write names it (Folder).
type Tarballs struct{}

var buildHash = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`) // SHA-1 today

func (Tarballs) Name() string { return "tarballs" }

func (Tarballs) Route(rest []string) (Item, error) {
	if len(rest) != 2 || !buildHash.MatchString(rest[1]) {
		return Item{}, errors.New("not <arch>/<hash>")
	}
	arch, h := rest[0], rest[1]
	return Item{Dir: arch + "/store/" + h[:2] + "/" + h}, nil
}

func (Tarballs) ObjectName(it Item, name string) error {
	arch, _, _ := strings.Cut(it.Dir, "/")
	stem, ok := strings.CutSuffix(name, "."+arch+".tar.gz")
	if !ok || stem == "" || strings.Contains(name, "/") {
		return errors.New("not <pkg>-<version>[-<revision>].<arch>.tar.gz of this architecture")
	}
	return nil
}

func init() { Register(Tarballs{}) }
