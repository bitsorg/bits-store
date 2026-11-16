// SPDX-License-Identifier: Apache-2.0

package index

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
)

// Keys are the manifest keys: Ed25519 public keys by id, as bits names them
// (sha256 of the raw key, 16 hex characters).
type Keys map[string]ed25519.PublicKey

// ParseKeys reads PEM public keys (bits' keys/*.pem).
func ParseKeys(pems []string) (Keys, error) {
	keys := Keys{}
	for i, p := range pems {
		b, rest := pem.Decode([]byte(p))
		if b == nil || len(bytes.TrimSpace(rest)) > 0 {
			return nil, fmt.Errorf("manifest_keys[%d]: not one PEM block", i)
		}
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		pub, ok := k.(ed25519.PublicKey)
		if err != nil || !ok {
			return nil, fmt.Errorf("manifest_keys[%d]: not an Ed25519 public key", i)
		}
		sum := sha256.Sum256(pub)
		keys[hex.EncodeToString(sum[:])[:16]] = pub
	}
	return keys, nil
}

// IDs is the keys' ids, sorted and joined: what a check was made with.
func (k Keys) IDs() string {
	ids := make([]string, 0, len(k))
	for id := range k {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return strings.Join(ids, ",")
}

// Verify checks a detached signature envelope ({"alg": "ed25519", "key_id", "sig"},
// as bits' trust.py writes it) over data: the id of the key that made it, or "".
// The envelope's key first, then every other, as bits does.
func (k Keys) Verify(data, envelope []byte) string {
	var env struct {
		Alg   string `json:"alg"`
		KeyID string `json:"key_id"`
		Sig   string `json:"sig"`
	}
	if json.Unmarshal(envelope, &env) != nil || env.Alg != "ed25519" {
		return ""
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return ""
	}
	if pub, ok := k[env.KeyID]; ok && ed25519.Verify(pub, data, sig) {
		return env.KeyID
	}
	for id, pub := range k {
		if id != env.KeyID && ed25519.Verify(pub, data, sig) {
			return id
		}
	}
	return ""
}
