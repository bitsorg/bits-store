// SPDX-License-Identifier: Apache-2.0

// Package format is what a package format adds to the store: how a path under
// a binding names an object. Everything else (tokens, volumes, staging and
// promote) is the core's. Formats are compiled in and register themselves.
package format

import (
	"fmt"
	"sort"
	"sync"
)

// Item is the object a path names: its Key, or a Dir holding one object, which the
// core finds (the first written) and a write names (Folder). Both are relative to
// the binding's key prefix and follow docs/TOKEN.md's path rules, or are refused.
type Item struct {
	Key, Dir string
}

// Format maps the path segments under a binding's prefix (one or more, each
// already checked) to an object, or returns an error: the path names nothing.
// Route is called concurrently and gets its own copy of the segments.
type Format interface {
	Name() string
	Route(rest []string) (Item, error)
}

// Mirror is a format whose missing objects the store fetches from a URL the
// client names; Origin says whether that URL may be the item's origin.
type Mirror interface {
	Origin(it Item, url string) error
}

// Folder is a format of Dir items: ObjectName says whether a write may give the
// object in it that name; First picks the object of several names (old stores).
type Folder interface {
	ObjectName(it Item, name string) error
	First(names []string) string
}

// Revisions is a format answering ?revisions on a path: {revision: hash} from the
// objects named <its key>-<revision>, each holding a hash. RevisionsOf checks the path.
type Revisions interface {
	RevisionsOf(rest []string) error
}

var (
	mu       sync.Mutex
	registry = map[string]Format{}
)

// Register makes a format available to bindings; a second one of a name panics.
func Register(f Format) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[f.Name()]; dup {
		panic(fmt.Sprintf("format %q registered twice", f.Name()))
	}
	registry[f.Name()] = f
}

// Lookup returns the format of a name.
func Lookup(name string) (Format, bool) {
	mu.Lock()
	defer mu.Unlock()
	f, ok := registry[name]
	return f, ok
}

// Names lists the registered formats, sorted.
func Names() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
