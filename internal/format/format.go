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

// Item is the object a path names. Key is relative to the binding's key prefix
// and must follow the path rules of docs/TOKEN.md: the core refuses it otherwise.
type Item struct {
	Key string
}

// Format maps the path segments under a binding's prefix (one or more, each
// already checked) to an object, or returns an error: the path names nothing.
// Route is called concurrently and gets its own copy of the segments.
type Format interface {
	Name() string
	Route(rest []string) (Item, error)
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
