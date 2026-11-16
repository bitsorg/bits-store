// SPDX-License-Identifier: Apache-2.0

package index

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

// What bits signs (testdata/manifests, by bits' trust.sign_bytes), bits-store verifies.
func TestVerifyWhatBitsSigns(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/manifests/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	keys, err := ParseKeys([]string{string(read("test-key.pem"))})
	if err != nil || keys.IDs() != "56475aa75463474c" {
		t.Fatalf("%v: %q", err, keys.IDs())
	}
	data, sig := read("common-manifest-el9.json"), read("common-manifest-el9.json.sig")
	if got := keys.Verify(data, sig); got != "56475aa75463474c" {
		t.Fatalf("not verified: %q", got)
	}
	if keys.Verify(append(data, ' '), sig) != "" {
		t.Fatal("other bytes verified")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if (Keys{"other": other}).Verify(data, sig) != "" || (Keys{}).Verify(data, sig) != "" {
		t.Fatal("verified with another key, or none")
	}
	// an envelope naming no key, or another one: every key is tried
	relabelled := strings.Replace(string(sig), "56475aa75463474c", "0000000000000000", 1)
	if keys.Verify(data, []byte(relabelled)) != "56475aa75463474c" {
		t.Fatal("a relabelled envelope not verified")
	}
	for _, bad := range []string{`{}`, `{"alg": "rsa", "sig": "AA=="}`, `{"alg": "ed25519", "sig": "%%"}`, `not json`} {
		if keys.Verify(data, []byte(bad)) != "" {
			t.Fatalf("%s verified", bad)
		}
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	notEd := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	two := string(read("test-key.pem")) + string(read("test-key.pem"))
	for _, bad := range []string{"", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", notEd, two} {
		if _, err := ParseKeys([]string{bad}); err == nil {
			t.Fatalf("%q taken as a key", bad)
		}
	}
}
