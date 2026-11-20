// SPDX-License-Identifier: Apache-2.0

package format

import (
	"errors"
	"regexp"
	"strings"
)

// Crates is a read-through mirror of a Cargo registry's sparse index: index/config.json
// the registry's configuration (its downloads here), index/<path> a crate's index file
// (1/<n>, 2/<n>, 3/<c>/<n>, <ab>/<cd>/<n>), crates/<crate>/<version>/download a crate,
// kept as files/<crate>/<crate>-<version>.crate once fetched.
type Crates struct{}

var (
	crateIndexName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`) // index paths are lower case
	crateName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	crateVersion   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]{1,64})?$`)
)

func (Crates) Name() string { return "crates" }

func (Crates) Route(rest []string) (Item, error) {
	n := len(rest)
	switch {
	case n == 2 && rest[0] == "index" && rest[1] == "config.json":
		return Item{Key: "index/config.json"}, nil
	case n >= 3 && rest[0] == "index" && crateIndexName.MatchString(rest[n-1]) &&
		CrateIndexPath(rest[n-1]) == strings.Join(rest[1:], "/"):
		return Item{Key: strings.Join(rest, "/")}, nil
	case n == 4 && rest[0] == "crates" && crateName.MatchString(rest[1]) && crateVersion.MatchString(rest[2]) &&
		rest[3] == "download":
		return Item{Key: "files/" + rest[1] + "/" + rest[1] + "-" + rest[2] + ".crate"}, nil
	}
	return Item{}, errors.New("not index/config.json, index/<crate's path> nor crates/<crate>/<version>/download")
}

// CrateIndexPath is where a sparse index keeps a crate's file (its name in lower case).
func CrateIndexPath(name string) string {
	switch len(name) {
	case 1:
		return "1/" + name
	case 2:
		return "2/" + name
	case 3:
		return "3/" + name[:1] + "/" + name
	}
	return name[:2] + "/" + name[2:4] + "/" + name
}

func init() { Register(Crates{}) }
