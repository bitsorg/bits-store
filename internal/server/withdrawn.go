// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Withdrawal is a gated binding's build withdrawn through the admin API, as a
// binding's deny withdraws one: by the sha256 it was stored with.
type Withdrawal struct {
	Binding string    `json:"binding"`
	SHA256  string    `json:"sha256"`        // sha256:<hex>
	Key     string    `json:"key,omitempty"` // the object the admin withdrew it from
	By      string    `json:"by"`            // the admin token's sub
	At      time.Time `json:"at"`
	Why     string    `json:"why"`
}

// withdrawals are kept in a file beside the index (-data), not in it: an index
// dropped and listed again must not give a withdrawn build back.
type withdrawals struct {
	mu   sync.Mutex
	path string
	list []Withdrawal
}

// openWithdrawals reads the file at path; none yet is an empty list.
func openWithdrawals(path string) (*withdrawals, error) {
	w := &withdrawals{path: path, list: []Withdrawal{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return w, nil
	} else if err != nil {
		return nil, err
	}
	var f struct{ Withdrawn []Withdrawal }
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	for _, x := range f.Withdrawn {
		if x.Binding == "" || !validSHA256(x.SHA256) {
			return nil, fmt.Errorf("%s: an entry without a binding or sha256:<hex>", path)
		}
	}
	w.list = append(w.list, f.Withdrawn...)
	return w, nil
}

func validSHA256(s string) bool {
	return len(s) == len("sha256:")+64 && s[:7] == "sha256:" && sha256Hex.MatchString(s[7:])
}

func (w *withdrawals) find(binding, sha string) int {
	return slices.IndexFunc(w.list, func(x Withdrawal) bool { return x.Binding == binding && x.SHA256 == sha })
}

// has says whether the build of sha is withdrawn from binding; any, whether one is.
func (w *withdrawals) has(binding, sha string) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.find(binding, sha) >= 0
}

func (w *withdrawals) any(binding string) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.ContainsFunc(w.list, func(x Withdrawal) bool { return x.Binding == binding })
}

func (w *withdrawals) all() []Withdrawal {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.list)
}

// add records x, unless its build is withdrawn already: then the first record, false.
func (w *withdrawals) add(x Withdrawal) (Withdrawal, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if i := w.find(x.Binding, x.SHA256); i >= 0 {
		return w.list[i], false, nil
	}
	return x, true, w.save(append(slices.Clone(w.list), x))
}

// lift removes the withdrawal of sha from binding; false when there is none.
func (w *withdrawals) lift(binding, sha string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	i := w.find(binding, sha)
	if i < 0 {
		return false, nil
	}
	return true, w.save(slices.Delete(slices.Clone(w.list), i, i+1))
}

// save writes list whole (a new file renamed over the old), then keeps it; under w.mu.
func (w *withdrawals) save(list []Withdrawal) error {
	b, err := json.MarshalIndent(map[string]any{"withdrawn": list}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(w.path), ".withdrawn-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // gone once renamed
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), w.path)
	}
	if err != nil {
		return err
	}
	w.list = list // as the file now is
	if err := syncDir(filepath.Dir(w.path)); err != nil {
		log.Printf("%s: the rename may not outlive a power loss: %v", w.path, err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
