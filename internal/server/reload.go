// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// CheckConfig reads a configuration file and builds a Server from it, as a start
// would: nil if the service would take it; with probe, each volume's keys must also
// list its bucket.
func CheckConfig(path string, probe bool) error {
	c, err := LoadConfig(path)
	if err != nil {
		return err
	}
	s, err := New(c)
	if err == nil && probe {
		err = probeErr(probeAll(context.Background(), s.stores))
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
	s.failingVolumes(s.now()) // probed now, not at the first /health
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
	s.uploads, s.fetches, s.now, s.index, s.reads, s.withdrawn, s.gc, s.pages = old.uploads, old.fetches, old.now, old.index, old.reads, old.withdrawn, old.gc, old.pages
	s.fetches.forgetFailures() // the new policy may allow what failed
	r.cur.Store(s)
	s.failingVolumes(s.now()) // probed now, not at the first /health
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
