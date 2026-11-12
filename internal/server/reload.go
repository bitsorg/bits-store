// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// CheckConfig reads a configuration file and builds a Server from it, as a start
// would: nil if the service would take it.
func CheckConfig(path string) error {
	c, err := LoadConfig(path)
	if err == nil {
		_, err = New(c)
	}
	return err
}

// Reloader serves with the current Server and rebuilds it when the configuration
// file's content changes. A configuration that fails the checks is logged once and
// the running one kept. Pending uploads and fetches carry over; cached tokens and failures do not.
type Reloader struct {
	path string
	seen [32]byte // the content last tried
	cur  atomic.Pointer[Server]
}

// NewReloader builds the Server from the file at path; its Config for the caller.
func NewReloader(path string) (*Reloader, *Config, error) {
	b, c, err := readConfig(path)
	if err != nil {
		return nil, nil, err
	}
	s, err := New(c)
	if err != nil {
		return nil, nil, err
	}
	r := &Reloader{path: path, seen: sha256.Sum256(b)}
	r.cur.Store(s)
	return r, c, nil
}

func (r *Reloader) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.cur.Load().ServeHTTP(w, req)
}

// Check reloads if the file changed; true when a new configuration is in force.
func (r *Reloader) Check() (bool, error) {
	b, c, err := readConfig(r.path)
	if b == nil {
		return false, err // unreadable: nothing tried
	}
	sum := sha256.Sum256(b)
	if sum == r.seen {
		return false, nil
	}
	r.seen = sum // a bad file is tried once; a partly written one changes again
	if err != nil {
		return false, err
	}
	old := r.cur.Load()
	s, err := New(c)
	if err != nil {
		return false, err
	}
	s.uploads, s.fetches, s.now = old.uploads, old.fetches, old.now
	s.fetches.forgetFailures() // the new policy may allow what failed
	r.cur.Store(s)
	return true, nil
}

// Watch calls Check every interval, logging each new outcome once.
func (r *Reloader) Watch(every time.Duration) {
	last := ""
	for range time.Tick(every) {
		ok, err := r.Check()
		switch {
		case ok:
			log.Printf("configuration %s reloaded", r.path)
			last = ""
		case err != nil && err.Error() != last:
			log.Printf("configuration %s not reloaded, the running one kept: %v", r.path, err)
			last = err.Error()
		}
	}
}
