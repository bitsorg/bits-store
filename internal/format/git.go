// SPDX-License-Identifier: Apache-2.0

package format

import (
	"errors"
	"regexp"
	"strings"
)

// Git mirrors git repositories for git's smart HTTP (protocol v2): <host>/<path>
// is https://<host>/<path>, the repository; info/refs and git-upload-pack under it
// are what git asks. The key is <host>/<path> without a trailing .git.
type Git struct{}

var gitHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)

func (Git) Name() string { return "git" }

func (Git) Route(rest []string) (Item, error) {
	n := len(rest)
	var repo []string
	switch {
	case n >= 4 && rest[n-2] == "info" && rest[n-1] == "refs":
		repo = rest[:n-2]
	case n >= 3 && rest[n-1] == "git-upload-pack":
		repo = rest[:n-1]
	default:
		return Item{}, errors.New("not <host>/<path>/info/refs nor <host>/<path>/git-upload-pack")
	}
	if !gitHost.MatchString(repo[0]) {
		return Item{}, errors.New("not a lower-case host name")
	}
	key := strings.TrimSuffix(strings.Join(repo, "/"), ".git")
	if strings.HasSuffix(key, "/") || key == repo[0] {
		return Item{}, errors.New("no repository path")
	}
	return Item{Key: key}, nil
}

func init() { Register(Git{}) }
