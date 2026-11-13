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

	"github.com/bitsorg/bits-store/internal/format"
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
	Fetch       FetchConf             `json:"fetch"`
	AccessLog   string                `json:"access_log"` // all, errors (default: and writes) or none
}

// FetchConf says where fetches may go (fetch.go). Site addresses (private ones and
// site_ranges) only for site_hosts; hosts outside trusted have a daily budget.
type FetchConf struct {
	SiteRanges []string `json:"site_ranges"`           // CIDRs of the site network
	SiteHosts  []string `json:"site_hosts"`            // host names on it a fetch may reach
	Trusted    []string `json:"trusted"`               // domains fetched from without a budget
	PerSubject int      `json:"untrusted_per_subject"` // fetches a day, per token subject; 0: 100
	PerDomain  int      `json:"untrusted_per_domain"`  // fetches a day, per domain; 0: 100
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

// Binding maps a logical prefix to a volume and key prefix; its format names
// the objects under it. Public bindings need no token.
type Binding struct {
	Prefix    string `json:"prefix"`     // "/sources/archives"
	Volume    string `json:"volume"`     // a key of Volumes
	KeyPrefix string `json:"key_prefix"` // "SOURCES/cache"; empty: bucket root
	Format    string `json:"format"`     // empty: "blob", the path is the key
	Public    bool   `json:"public"`
	MaxSize   int64  `json:"max_size"` // bytes a fetch may bring (Mirror formats); 0: 32 GiB
	segs      []string
	format    format.Format
	mirror    format.Mirror    // the format, when it fetches what is missing
	folder    format.Folder    // the format, when its items are folders holding one object
	revisions format.Revisions // the format, when it answers ?revisions
}

const defaultMaxSize = 32 << 30

// unprefixed is a key or folder relative to the binding's key prefix, as its format names it.
func (b *Binding) unprefixed(k string) string {
	if b.KeyPrefix == "" {
		return k
	}
	return strings.TrimPrefix(k, b.KeyPrefix+"/")
}

// LoadConfig reads and checks a configuration file.
func LoadConfig(path string) (*Config, error) {
	_, c, err := readConfig(path)
	return c, err
}

// readConfig is LoadConfig with the bytes it parsed.
func readConfig(path string) ([]byte, *Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	c, err := parseConfig(b, path)
	return b, c, err
}

func parseConfig(b []byte, path string) (*Config, error) {
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
		if b.Format == "" {
			b.Format = "blob"
		}
		if b.format, ok = format.Lookup(b.Format); !ok {
			return nil, fmt.Errorf("binding %q: no format %q (have %s)", b.Prefix, b.Format,
				strings.Join(format.Names(), ", "))
		}
		b.mirror, _ = b.format.(format.Mirror)
		b.folder, _ = b.format.(format.Folder)
		b.revisions, _ = b.format.(format.Revisions)
		switch {
		case b.mirror == nil && b.MaxSize != 0:
			return nil, fmt.Errorf("binding %q: max_size is for formats that fetch", b.Prefix)
		case b.MaxSize < 0 || b.MaxSize > maxFetch:
			return nil, fmt.Errorf("binding %q: max_size up to %d", b.Prefix, int64(maxFetch))
		case b.mirror != nil && b.MaxSize == 0:
			b.MaxSize = defaultMaxSize
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
