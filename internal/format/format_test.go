// SPDX-License-Identifier: Apache-2.0

package format

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

// routeCase is one conformance case: the segments under a prefix, and the key
// they name ("" when the path names nothing).
type routeCase struct {
	rest []string
	key  string
}

// conformance holds every registered format's cases; a format without any fails.
var conformance = map[string][]routeCase{
	"blob": {
		{[]string{"x"}, "x"},
		{[]string{"x86_64-el10-gcc14-opt", "ab", "h"}, "x86_64-el10-gcc14-opt/ab/h"},
		{nil, ""},
	},
	"tarballs": {
		{[]string{"x86_64-el9", "0123456789abcdef0123456789abcdef01234567"}, "dir:x86_64-el9/store/01/0123456789abcdef0123456789abcdef01234567"},
		{[]string{"x86_64-el9", "0123456789ABCDEF0123456789abcdef01234567"}, ""},
		{[]string{"x86_64-el9", "0123456789abcdef"}, ""},
		{[]string{"x86_64-el9", "0123456789abcdef0123456789abcdef01234567", "f.tar.gz"}, ""},
		{[]string{"0123456789abcdef0123456789abcdef01234567"}, ""},
	},
	"sources": {
		{[]string{"9e", "9e107d9d372bb6826bd81d3542a419d6", "a.tar.gz"}, "9e/9e107d9d372bb6826bd81d3542a419d6/a.tar.gz"},
		{[]string{"9f", "9e107d9d372bb6826bd81d3542a419d6", "a.tar.gz"}, ""},
		{[]string{"9e", "9E107D9D372BB6826BD81D3542A419D6", "a.tar.gz"}, ""},
		{[]string{"9e", "9e107d9d372bb6826bd81d3542a419d", "a.tar.gz"}, ""},
		{[]string{"9e", "9e107d9d372bb6826bd81d3542a419d6"}, ""},
		{[]string{"9e", "9e107d9d372bb6826bd81d3542a419d6", "a", "b"}, ""},
	},
}

func TestConformance(t *testing.T) {
	for _, name := range Names() {
		f, _ := Lookup(name)
		cases := conformance[name]
		if len(cases) == 0 {
			t.Errorf("%s: no conformance cases", name)
		}
		for _, c := range cases {
			it, err := f.Route(c.rest)
			got := it.Key
			if it.Dir != "" {
				got = "dir:" + it.Dir // a folder item, the object found in it
			}
			if c.key == "" && err == nil || c.key != "" && (err != nil || got != c.key) {
				t.Errorf("%s: Route(%q) = %q, %v; want %q", name, c.rest, got, err, c.key)
			}
		}
	}
}

func TestRegisterTwicePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a second blob was accepted")
		}
	}()
	Register(Blob{})
}

// keyOf is the sources key of a URL, as bits names its cache.
func keyOf(u string) Item {
	sum := md5.Sum([]byte(u))
	h := hex.EncodeToString(sum[:])
	return Item{Key: h[:2] + "/" + h + "/" + u[strings.LastIndex(u, "/")+1:]}
}

func TestSourcesOrigin(t *testing.T) {
	const src = "https://example.org/dl/pkg-1.0.tar.gz"
	if err := (Sources{}).Origin(keyOf(src), src); err != nil {
		t.Fatalf("the URL of its own path refused: %v", err)
	}
	if err := (Sources{}).Origin(keyOf("http://example.org/pkg-1.0.tar.gz"), "http://example.org/pkg-1.0.tar.gz"); err != nil {
		t.Fatalf("plain http refused: %v", err)
	}
	for _, other := range []string{src + "?x", "https://example.org/dl/v2/pkg-1.0.tar.gz"} {
		if (Sources{}).Origin(keyOf(src), other) == nil {
			t.Errorf("%s accepted for the path of %s", other, src)
		}
	}
	h := strings.Split(keyOf(src).Key, "/")[1]
	if (Sources{}).Origin(Item{Key: h[:2] + "/" + h + "/other.tar.gz"}, src) == nil {
		t.Error("a file other than the URL's last segment accepted")
	}
	for _, bad := range []string{
		"ftp://example.org/dl/pkg-1.0.tar.gz",
		"https://user@example.org/dl/pkg-1.0.tar.gz",
		"https:///dl/pkg-1.0.tar.gz",
		"https://example.org/dl/pkg\x01.tar.gz",
		"https://example.org/dl/pkg-é.tar.gz",
		"file:///etc/passwd",
	} {
		if (Sources{}).Origin(keyOf(bad), bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestTarballNames(t *testing.T) {
	it, _ := (Tarballs{}).Route([]string{"x86_64-el9", "0123456789abcdef0123456789abcdef01234567"})
	for name, ok := range map[string]bool{
		"ROOT-6.32.02-1.x86_64-el9.tar.gz": true,
		"zlib-v1.3.x86_64-el9.tar.gz":      true,
		"ROOT-6.32.02-1.x86_64-el8.tar.gz": false,
		"ROOT-6.32.02-1.x86_64-el9.tgz":    false,
		".x86_64-el9.tar.gz":               false,
		"a/b.x86_64-el9.tar.gz":            false,
	} {
		if err := (Tarballs{}).ObjectName(it, name); (err == nil) != ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
