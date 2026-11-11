// SPDX-License-Identifier: Apache-2.0

package format

import "testing"

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
			if c.key == "" && err == nil || c.key != "" && (err != nil || it.Key != c.key) {
				t.Errorf("%s: Route(%q) = %q, %v; want %q", name, c.rest, it.Key, err, c.key)
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
