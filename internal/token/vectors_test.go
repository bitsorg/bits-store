// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// decide is the order of checks in docs/TOKEN.md: path, then token, then capabilities.
func decide(v *Verifier, tok, method, path string, now time.Time) string {
	segs, err := ParsePath(path)
	if err != nil {
		return "bad-path"
	}
	t, err := v.Verify(tok, now)
	if err != nil {
		return "invalid"
	}
	if t.Allows(method, segs) {
		return "allow"
	}
	return "deny"
}

type vectors struct {
	Issuer, Audience string
	Now              int64
	MaxLifetime      int64 `json:"max_lifetime"`
	Keys             map[string]struct{ X, Signer string }
	Cases            []struct{ Name, Token, Method, Path, Outcome string }
}

func load(t *testing.T) (*Verifier, *vectors) {
	var vec vectors
	b, err := os.ReadFile("../../testdata/tokens/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vec); err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Issuer: vec.Issuer, Audience: vec.Audience, Keys: map[string]Key{},
		MaxLifetime: time.Duration(vec.MaxLifetime) * time.Second}
	for kid, k := range vec.Keys {
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("key %s", kid)
		}
		v.Keys[kid] = Key{Public: pub, Signer: k.Signer}
	}
	if err := v.Check(); err != nil {
		t.Fatal(err)
	}
	return v, &vec
}

func TestVectors(t *testing.T) {
	v, vec := load(t)
	if len(vec.Cases) < 100 {
		t.Fatalf("only %d cases", len(vec.Cases))
	}
	for _, c := range vec.Cases {
		if got := decide(v, c.Token, c.Method, c.Path, time.Unix(vec.Now, 0)); got != c.Outcome {
			t.Errorf("%s: want %s, got %s", c.Name, c.Outcome, got)
		}
	}
}

func TestDenyList(t *testing.T) {
	v, vec := load(t)
	c := vec.Cases[0] // an allowed case
	now := time.Unix(vec.Now, 0)
	v.Denied = func(jti string) bool { return false }
	if _, err := v.Verify(c.Token, now); err != nil {
		t.Fatalf("%s refused: %v", c.Name, err)
	}
	v.Denied = func(jti string) bool { return jti == "t-1" }
	if _, err := v.Verify(c.Token, now); err == nil {
		t.Fatalf("%s: denied jti accepted", c.Name)
	}
}

func TestGlobIsFast(t *testing.T) {
	start := time.Now()
	if segMatch("*a*a*a*b", strings.Repeat("a", maxSegment)) {
		t.Fatal("matched")
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("took %v", time.Since(start))
	}
}

func TestTimeRange(t *testing.T) {
	// 2^53 is past the range; the vectors cannot reach it through a valid lifetime
	if _, err := timeClaim(json.RawMessage("9007199254740991")); err != nil {
		t.Fatal(err)
	}
	if _, err := timeClaim(json.RawMessage("9007199254740992")); err == nil {
		t.Fatal("2^53 accepted")
	}
}

func TestCheck(t *testing.T) {
	v, _ := load(t)
	k := v.Keys["build-1"]
	k.Signer = "bulid"
	v.Keys["build-1"] = k
	if v.Check() == nil {
		t.Fatal("misspelt signer accepted")
	}
}

func TestConcurrent(t *testing.T) {
	// one Verifier serves every request; run with -race
	v, vec := load(t)
	now := time.Unix(vec.Now, 0)
	done := make(chan string)
	for i := 0; i < 32; i++ {
		go func(i int) {
			c := vec.Cases[i%len(vec.Cases)]
			for j := 0; j < 50; j++ {
				if got := decide(v, c.Token, c.Method, c.Path, now); got != c.Outcome {
					done <- c.Name
					return
				}
			}
			done <- ""
		}(i)
	}
	for i := 0; i < 32; i++ {
		if name := <-done; name != "" {
			t.Errorf("%s changed under concurrency", name)
		}
	}
}
