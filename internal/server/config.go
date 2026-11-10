// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bitsorg/bits-store/internal/token"
)

// Config is the service's configuration file (JSON). Secrets are not in it: a
// volume names the environment variables that hold its S3 keys.
type Config struct {
	Listen      string                `json:"listen"`
	Issuer      string                `json:"issuer"`
	Audience    string                `json:"audience"`
	MaxLifetime string                `json:"max_lifetime"` // e.g. "168h"; empty: 7 days
	URLLifetime string                `json:"url_lifetime"` // presigned URLs; empty: 5m
	Keys        map[string]KeyConfig  `json:"keys"`
	Volumes     map[string]VolumeConf `json:"volumes"`
	Bindings    []Binding             `json:"bindings"`
}

// KeyConfig is a token signing key: raw Ed25519 public key, base64url.
type KeyConfig struct {
	X      string `json:"x"`
	Signer string `json:"signer"`
}

// VolumeConf is an S3 bucket. With no key variables, URLs are presigned
// anonymously, which works only for a public bucket.
type VolumeConf struct {
	Endpoint     string `json:"endpoint"` // https://s3.cern.ch
	Bucket       string `json:"bucket"`
	Region       string `json:"region"` // set, so presigning needs no network
	AccessKeyEnv string `json:"access_key_env"`
	SecretKeyEnv string `json:"secret_key_env"`
	AllowHTTP    bool   `json:"allow_http"` // a test MinIO; never for real keys
}

// Binding maps a logical prefix to a volume and key prefix. Public bindings
// need no token.
type Binding struct {
	Prefix    string `json:"prefix"`     // "/sources/archives"
	Volume    string `json:"volume"`     // a key of Volumes
	KeyPrefix string `json:"key_prefix"` // "SOURCES/cache"; empty: bucket root
	Public    bool   `json:"public"`
	segs      []string
}

// LoadConfig reads and checks a configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil || dec.More() {
		return nil, fmt.Errorf("%s: not one JSON object: %v", path, err)
	}
	return &c, nil
}

func duration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

// verifier builds the token verifier from the configuration and checks it.
func (c *Config) verifier() (*token.Verifier, error) {
	life, err := duration(c.MaxLifetime, 0)
	if err != nil || c.MaxLifetime != "" && life <= 0 {
		return nil, fmt.Errorf("max_lifetime: a positive duration, or empty for 7 days")
	}
	v := &token.Verifier{Issuer: c.Issuer, Audience: c.Audience, MaxLifetime: life, Keys: map[string]token.Key{}}
	for kid, k := range c.Keys {
		pub, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: not a base64url Ed25519 public key", kid)
		}
		v.Keys[kid] = token.Key{Public: pub, Signer: k.Signer}
	}
	return v, v.Check()
}

// bindings checks the bindings and orders them longest prefix first. Within one
// bucket, key prefixes must not overlap: authorisation is on the logical path, so
// two bindings reaching the same keys would let one prefix's token read the other's.
func (c *Config) bindings() ([]Binding, error) {
	if len(c.Bindings) == 0 {
		return nil, fmt.Errorf("no bindings")
	}
	seen := map[string]bool{}
	byBucket := map[string][]string{} // endpoint and bucket -> key prefixes
	where := func(v VolumeConf) string {
		return normEndpoint(v.Endpoint) + " " + v.Bucket
	}
	staged := map[string]bool{} // buckets a keyed volume writes STAGING/ into
	for _, v := range c.Volumes {
		if v.AccessKeyEnv != "" {
			staged[where(v)] = true
		}
	}
	out := make([]Binding, 0, len(c.Bindings))
	for _, b := range c.Bindings {
		segs, err := token.ParsePath(b.Prefix)
		if err != nil || seen[b.Prefix] {
			return nil, fmt.Errorf("binding %q: bad or duplicate prefix", b.Prefix)
		}
		vol, ok := c.Volumes[b.Volume]
		if !ok {
			return nil, fmt.Errorf("binding %q: no volume %q", b.Prefix, b.Volume)
		}
		if b.KeyPrefix != "" {
			if _, err := token.ParsePath("/" + b.KeyPrefix); err != nil {
				return nil, fmt.Errorf("binding %q: key_prefix breaks the path rules", b.Prefix)
			}
		}
		if staged[where(vol)] && overlap(b.KeyPrefix, stagingPrefix) {
			return nil, fmt.Errorf("binding %q: key_prefix overlaps the staging prefix %s", b.Prefix, stagingPrefix)
		}
		for _, other := range byBucket[where(vol)] {
			if overlap(other, b.KeyPrefix) {
				return nil, fmt.Errorf("binding %q: key_prefix %q overlaps %q in the same bucket", b.Prefix, b.KeyPrefix, other)
			}
		}
		byBucket[where(vol)] = append(byBucket[where(vol)], b.KeyPrefix)
		seen[b.Prefix] = true
		b.segs = segs
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].segs) > len(out[j].segs) })
	return out, nil
}

// overlap reports whether two key prefixes reach common keys: one is empty, equal
// to, or a whole-segment prefix of the other.
func overlap(a, b string) bool {
	return a == "" || b == "" || a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// normEndpoint spells an endpoint one way: lower-case host, no default port.
func normEndpoint(e string) string {
	u, err := url.Parse(e)
	if err != nil {
		return e
	}
	host := strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" && !(u.Scheme == "https" && p == "443" || u.Scheme == "http" && p == "80") {
		host += ":" + p
	}
	return u.Scheme + "://" + host
}
