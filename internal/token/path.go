// SPDX-License-Identifier: Apache-2.0

package token

import (
	"errors"
	"strings"
)

// ErrBadPath is returned for a request path or pattern that breaks docs/TOKEN.md.
var ErrBadPath = errors.New("bad path")

const maxSegment = 255

// segChar reports whether c may appear in a path segment (no '%': nothing is decoded).
func segChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		strings.IndexByte("._~+!@=,:-", c) >= 0
}

func split(p string, star bool) ([]string, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, ErrBadPath
	}
	segs := strings.Split(p[1:], "/")
	for _, s := range segs {
		if len(s) == 0 || len(s) > maxSegment || s == "." || s == ".." {
			return nil, ErrBadPath
		}
		for i := 0; i < len(s); i++ {
			if !segChar(s[i]) && !(star && s[i] == '*') {
				return nil, ErrBadPath
			}
		}
	}
	return segs, nil
}

// ParsePath splits a request path, exactly as sent and without its query, into segments.
func ParsePath(p string) ([]string, error) { return split(p, false) }

// ParsePattern splits a capability pattern; "**" is allowed only as the whole last segment.
func ParsePattern(p string) ([]string, error) {
	segs, err := split(p, true)
	if err != nil {
		return nil, err
	}
	for i, s := range segs {
		if s == "**" && i == len(segs)-1 {
			continue
		}
		if strings.Contains(s, "**") || strings.Count(s, "*") > 4 {
			return nil, ErrBadPath
		}
	}
	return segs, nil
}

// segMatch matches one segment against a pattern segment where '*' matches any run
// of characters; it backtracks only to the last '*', so it stays linear in practice.
func segMatch(pat, s string) bool {
	i, j, star, mark := 0, 0, -1, 0
	for j < len(s) {
		switch {
		case i < len(pat) && pat[i] != '*' && pat[i] == s[j]:
			i++
			j++
		case i < len(pat) && pat[i] == '*':
			star, mark = i, j
			i++
		case star >= 0:
			i, mark = star+1, mark+1
			j = mark
		default:
			return false
		}
	}
	for ; i < len(pat); i++ {
		if pat[i] != '*' {
			return false
		}
	}
	return true
}

// Match reports whether parsed path segments match a parsed pattern.
func Match(pat, segs []string) bool {
	n := len(pat)
	if pat[n-1] == "**" {
		if len(segs) < n {
			return false
		}
		n--
	} else if len(segs) != n {
		return false
	}
	for k := 0; k < n; k++ {
		if !segMatch(pat[k], segs[k]) {
			return false
		}
	}
	return true
}
