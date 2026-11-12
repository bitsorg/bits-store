// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

const defaultDaily = 100 // fetches a day from untrusted domains, per subject and per domain

// fetchPolicy is where fetches may go: never loopback, link-local or the host
// itself; the site network (private addresses, site_ranges) only for site_hosts.
type fetchPolicy struct {
	site                  []netip.Prefix
	siteHosts             map[string]bool
	trusted               []string
	perSubject, perDomain int
}

var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

func newPolicy(c FetchConf) (*fetchPolicy, error) {
	p := &fetchPolicy{siteHosts: map[string]bool{}, perSubject: c.PerSubject, perDomain: c.PerDomain}
	for _, r := range c.SiteRanges {
		pr, err := netip.ParsePrefix(r)
		if err != nil || pr.Addr().Is4In6() { // addresses are checked unmapped
			return nil, fmt.Errorf("fetch.site_ranges: %q is not a CIDR (IPv4 ranges as IPv4)", r)
		}
		p.site = append(p.site, pr.Masked())
	}
	for _, h := range c.SiteHosts {
		if _, err := netip.ParseAddr(h); err == nil || !hostName.MatchString(h) {
			return nil, fmt.Errorf("fetch.site_hosts: %q is not a lower-case host name", h)
		}
		p.siteHosts[h] = true
	}
	for _, d := range c.Trusted {
		if !hostName.MatchString(d) {
			return nil, fmt.Errorf("fetch.trusted: %q is not a lower-case domain", d)
		}
		p.trusted = append(p.trusted, d)
	}
	if p.perSubject < 0 || p.perDomain < 0 {
		return nil, fmt.Errorf("fetch: daily budgets are counts, 0 for the default %d", defaultDaily)
	}
	if p.perSubject == 0 {
		p.perSubject = defaultDaily
	}
	if p.perDomain == 0 {
		p.perDomain = defaultDaily
	}
	return p, nil
}

// fetchAllowed says whether a fetch may connect to address a of host.
var fetchAllowed = func(p *fetchPolicy, host string, a netip.Addr) bool {
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || own(a) {
		return false
	}
	for _, r := range p.site {
		if r.Contains(a) {
			return p.siteHosts[host]
		}
	}
	return public(a) || p.siteHosts[host] && a.IsPrivate()
}

// isTrusted reports whether host is a trusted domain or under one.
func (p *fetchPolicy) isTrusted(host string) bool {
	for _, d := range p.trusted {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// domainOf is what a domain's budget counts: an address as is, else the last two
// labels (a.example.org and b.example.org share one).
func domainOf(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	labels := strings.Split(host, ".")
	return strings.Join(labels[max(0, len(labels)-2):], ".")
}

// client resolves each host itself and connects only to the addresses it allows,
// redirects included; no proxy, no Accept-Encoding (the bytes stored are those served).
func (p *fetchPolicy) client() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second} // per address, tried in turn
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		err = errNotAllowed // also when the name has no address
		for _, a := range ips {
			if a = a.Unmap(); !fetchAllowed(p, host, a) {
				err = fmt.Errorf("%w (%s is %s)", errNotAllowed, host, a) // logged, not answered
				continue
			}
			c, derr := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if derr == nil {
				return c, nil
			}
			err = derr
		}
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
		DisableCompression:    true,
		MaxIdleConns:          maxFetching,
		IdleConnTimeout:       90 * time.Second,
	}}
}

var errNotAllowed = fetchError("the origin's address is not one a fetch may reach")

var interfaceAddrs = net.InterfaceAddrs // tests give public ones

// own reports whether a is one of the host's addresses.
func own(a netip.Addr) bool {
	addrs, err := interfaceAddrs()
	if err != nil {
		return true
	}
	for _, x := range addrs {
		if n, ok := x.(*net.IPNet); ok {
			if b, ok := netip.AddrFromSlice(n.IP); ok && b.Unmap() == a {
				return true
			}
		}
	}
	return false
}

var global6 = netip.MustParsePrefix("2000::/3")

// nonPublic are global-looking ranges that are not, or that embed IPv4 addresses.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// public reports whether an address is on the public internet: not private,
// loopback, link-local, multicast or reserved.
func public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.Is6() && !global6.Contains(a) {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
