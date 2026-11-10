// SPDX-License-Identifier: Apache-2.0

// Package token verifies store tokens as specified in docs/TOKEN.md.
package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxLen             = 4000
	Typ                = "bits-store+jwt"
	Leeway             = 60
	DefaultMaxLifetime = 7 * 24 * time.Hour
	maxTime            = 1<<53 - 1
)

// Key is a verification key and the kind of signer that holds its private half.
type Key struct {
	Public ed25519.PublicKey
	Signer string // "user" (bits-console) or "build" (the orchestrator)
}

// Verifier holds what a site configures to check tokens.
type Verifier struct {
	Issuer, Audience string
	Keys             map[string]Key
	MaxLifetime      time.Duration         // 0: DefaultMaxLifetime
	Denied           func(jti string) bool // the deny-list; nil: none
}

// Cap is one capability: a method and a parsed pattern.
type Cap struct {
	Method  string
	Pattern []string
}

// Token is a verified token.
type Token struct {
	Sub, Grp, Jti string
	Iat, Exp      int64
	Caps          []Cap
}

var (
	tokenChars = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	intLiteral = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
	known      = strings.Fields("alg typ kid iss aud sub grp iat exp jti cap nbf m p")
)

func invalid(format string, a ...any) error { return fmt.Errorf("invalid token: "+format, a...) }

// Check refuses a configuration that would accept or refuse tokens by accident.
// A Verifier is read-only once checked, so it is safe for concurrent requests
// (Denied must be too).
func (v *Verifier) Check() error {
	if v.Issuer == "" || v.Audience == "" || len(v.Keys) == 0 || v.MaxLifetime < 0 ||
		v.MaxLifetime != 0 && v.MaxLifetime < time.Minute {
		return errors.New("token verifier: issuer, audience, keys and lifetime needed")
	}
	for kid, k := range v.Keys {
		if len(k.Public) != ed25519.PublicKeySize || k.Signer != "user" && k.Signer != "build" {
			return fmt.Errorf("token verifier: key %q: 32-byte key and signer user or build needed", kid)
		}
	}
	return nil
}

// Verify checks a token at time now and returns its claims and parsed capabilities.
func (v *Verifier) Verify(tok string, now time.Time) (*Token, error) {
	if len(tok) == 0 || len(tok) > MaxLen || !tokenChars.MatchString(tok) || strings.Count(tok, ".") != 2 {
		return nil, invalid("form")
	}
	parts := strings.Split(tok, ".")
	header, err := decodeObject(parts[0])
	if err != nil {
		return nil, invalid("header: %v", err)
	}
	if len(header) != 3 || str(header["alg"]) != "EdDSA" || str(header["typ"]) != Typ {
		return nil, invalid("header")
	}
	key, ok := v.Keys[str(header["kid"])]
	if !ok || !isString(header["kid"]) {
		return nil, invalid("unknown kid")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(key.Public) != ed25519.PublicKeySize ||
		!ed25519.Verify(key.Public, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, invalid("signature")
	}
	c, err := decodeObject(parts[1])
	if err != nil {
		return nil, invalid("payload: %v", err)
	}
	if _, has := c["nbf"]; has {
		return nil, invalid("nbf")
	}
	t := &Token{}
	var iss, aud string
	for name, dst := range map[string]*string{"iss": &iss, "aud": &aud, "sub": &t.Sub, "grp": &t.Grp, "jti": &t.Jti} {
		if err := json.Unmarshal(c[name], dst); err != nil || !isString(c[name]) {
			return nil, invalid("claim %s", name)
		}
	}
	if strings.HasPrefix(t.Sub, "build:") != (key.Signer == "build") {
		return nil, invalid("subject does not fit the key's signer")
	}
	if t.Iat, err = timeClaim(c["iat"]); err != nil {
		return nil, invalid("iat")
	}
	if t.Exp, err = timeClaim(c["exp"]); err != nil {
		return nil, invalid("exp")
	}
	maxLife := v.MaxLifetime
	if maxLife == 0 {
		maxLife = DefaultMaxLifetime
	}
	n := now.Unix()
	if iss != v.Issuer || aud != v.Audience || t.Exp <= t.Iat || n > t.Exp+Leeway ||
		t.Iat > n+Leeway || t.Exp-t.Iat > int64(maxLife/time.Second) {
		return nil, invalid("claims")
	}
	if v.Denied != nil && v.Denied(t.Jti) {
		return nil, invalid("denied")
	}
	if t.Caps, err = caps(c["cap"]); err != nil {
		return nil, invalid("cap: %v", err)
	}
	return t, nil
}

// Allows reports whether the token grants method on the parsed path; HEAD counts as GET.
func (t *Token) Allows(method string, segs []string) bool {
	if method == "HEAD" {
		method = "GET"
	}
	for _, c := range t.Caps {
		if c.Method == method && Match(c.Pattern, segs) {
			return true
		}
	}
	return false
}

func caps(raw json.RawMessage) ([]Cap, error) {
	var list []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		return nil, errors.New("not a non-empty list")
	}
	out := make([]Cap, 0, len(list))
	for _, e := range list {
		var m map[string]json.RawMessage
		if len(e) == 0 || e[0] != '{' || json.Unmarshal(e, &m) != nil || len(m) != 2 ||
			!isString(m["m"]) || !isString(m["p"]) {
			return nil, errors.New("entry")
		}
		method, p := str(m["m"]), str(m["p"])
		if method != "GET" && method != "PUT" {
			return nil, fmt.Errorf("method %q", method)
		}
		pat, err := ParsePattern(p)
		if err != nil {
			return nil, fmt.Errorf("pattern %q", p)
		}
		out = append(out, Cap{method, pat})
	}
	return out, nil
}

// decodeObject decodes one base64url part as a strict JSON object (docs/TOKEN.md,
// "Strict JSON"); member names are checked on the raw text, since encoding/json
// itself matches names ignoring case.
func decodeObject(part string) (map[string]json.RawMessage, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(part)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(b) || !json.Valid(b) {
		return nil, errors.New("not UTF-8 JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // any number in an ignored claim must not fail the walk
	if err := checkNames(dec); err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if len(b) == 0 || bytes.TrimLeft(b, " \t\r\n")[0] != '{' || json.Unmarshal(b, &m) != nil {
		return nil, errors.New("not an object")
	}
	return m, nil
}

// checkNames walks every object in one JSON value: names ASCII, no duplicates, and
// no name equal to a known one except for ASCII case.
func checkNames(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			name, err := dec.Token()
			if err != nil {
				return err
			}
			if err := checkName(name.(string), seen); err != nil {
				return err
			}
			if err := checkNames(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
	case json.Delim('['):
		for dec.More() {
			if err := checkNames(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
	}
	return err
}

func checkName(name string, seen map[string]bool) error {
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			return errors.New("non-ASCII member name")
		}
	}
	if seen[name] {
		return fmt.Errorf("duplicate member %q", name)
	}
	seen[name] = true
	for _, k := range known {
		if name != k && strings.EqualFold(name, k) { // both ASCII here
			return fmt.Errorf("member %q differs from %q in case", name, k)
		}
	}
	return nil
}

func isString(raw json.RawMessage) bool { return len(raw) > 0 && raw[0] == '"' }

func str(raw json.RawMessage) string {
	var s string
	if !isString(raw) || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// timeClaim accepts only a plain integer literal from 0 to 2^53-1, so no arithmetic
// on it can overflow.
func timeClaim(raw json.RawMessage) (int64, error) {
	if !intLiteral.Match(raw) {
		return 0, errors.New("not an integer literal")
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil || n > maxTime {
		return 0, errors.New("out of range")
	}
	return n, nil
}
