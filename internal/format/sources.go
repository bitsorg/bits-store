// SPDX-License-Identifier: Apache-2.0

package format

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Sources is bits' source archive cache: <md5[:2]>/<md5>/<file>, the MD5 of the
// URL as the recipe spells it, file the URL's last segment. The store fetches a
// missing archive from that URL (Mirror).
type Sources struct{}

var md5Hex = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (Sources) Name() string { return "sources" }

func (Sources) Route(rest []string) (Item, error) {
	if len(rest) != 3 || !md5Hex.MatchString(rest[1]) || rest[0] != rest[1][:2] {
		return Item{}, errors.New("not <md5[:2]>/<md5>/<file>")
	}
	return Item{Key: strings.Join(rest, "/")}, nil
}

func (Sources) Origin(it Item, src string) error {
	parts := strings.Split(it.Key, "/")
	if len(parts) != 3 {
		return errors.New("not a sources key")
	}
	for _, c := range src {
		if c <= ' ' || c > '~' {
			return errors.New("the URL has spaces, controls or non-ASCII")
		}
	}
	u, err := url.Parse(src)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("not an http(s)://host URL")
	}
	if sum := md5.Sum([]byte(src)); hex.EncodeToString(sum[:]) != parts[1] {
		return errors.New("the URL's MD5 is not the path's")
	}
	if src[strings.LastIndex(src, "/")+1:] != parts[2] {
		return errors.New("the file is not the URL's last segment")
	}
	return nil
}

func init() { Register(Sources{}) }
