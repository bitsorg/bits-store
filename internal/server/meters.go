// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"maps"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bitsorg/bits-store/internal/index"
)

// meters counts what the service does, for /metrics: requests by binding, fills
// from upstream by format. In memory, shared by a reload; a restart starts again.
type meters struct {
	mu        sync.Mutex
	start     time.Time
	requests  map[[4]string]int64 // binding, format, method, code
	seconds   map[[2]string]*histogram
	bytes     map[[2]string]int64
	fills     map[[2]string]int64 // format, result
	fillBytes map[string]int64
	refused   map[[2]string]int64       // format, reason
	hosts     map[[3]string]*index.Fill // day, format, host: for the index, until flushed
	hostsDay  string
	seen      map[[2]string]bool // format, host: today's, at most maxFillHosts
	folded    int64              // fetches counted as "(other)", until flushed
}

// maxFillHosts bounds the hosts counted a day; the rest count as "(other)".
const maxFillHosts = 1000

// requestBuckets are the request durations' histogram bounds (seconds).
var requestBuckets = []float64{0.005, 0.025, 0.1, 0.5, 2.5, 10, 60}

type histogram struct {
	counts []int64 // per bucket, then +Inf
	sum    float64
}

func newMeters(now time.Time) *meters {
	return &meters{start: now, requests: map[[4]string]int64{}, seconds: map[[2]string]*histogram{},
		bytes: map[[2]string]int64{}, fills: map[[2]string]int64{}, fillBytes: map[string]int64{},
		refused: map[[2]string]int64{}, hosts: map[[3]string]*index.Fill{}}
}

func bindingOf(b *Binding) [2]string {
	if b == nil {
		return [2]string{"(none)", ""}
	}
	return [2]string{b.Prefix, b.Format}
}

// request counts one answered request, its bytes and how long it took.
func (m *meters) request(b *Binding, method string, code int, n int64, d time.Duration) {
	k := bindingOf(b)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[[4]string{k[0], k[1], method, strconv.Itoa(code)}]++
	m.bytes[k] += n
	h := m.seconds[k]
	if h == nil {
		h = &histogram{counts: make([]int64, len(requestBuckets)+1)}
		m.seconds[k] = h
	}
	i, _ := slices.BinarySearch(requestBuckets, d.Seconds())
	h.counts[i]++
	h.sum += d.Seconds()
}

// fill counts a fetch from upstream host: done or failed, and its bytes.
func (m *meters) fill(format, host string, n int64, err error) {
	result := "ok"
	if err != nil {
		result = "failed"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fills[[2]string{format, result}]++
	m.fillBytes[format] += n
	f := m.host(format, host)
	f.Bytes += n
	if err != nil {
		f.Failed++
	} else {
		f.OK++
	}
}

// refuse counts a fetch not started: "full" (no room) or "throttled" (budget spent).
func (m *meters) refuse(format, host, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refused[[2]string{format, reason}]++
	m.host(format, host).Refused++
}

// host is today's count of a format's fetches from host (m.mu held).
func (m *meters) host(format, host string) *index.Fill {
	day := time.Now().UTC().Format(time.DateOnly)
	if day != m.hostsDay {
		m.hostsDay, m.seen = day, map[[2]string]bool{}
	}
	h := [2]string{format, host}
	if !m.seen[h] && len(m.seen) >= maxFillHosts {
		h[1] = "(other)"
		m.folded++
	} else {
		m.seen[h] = true
	}
	k := [3]string{day, h[0], h[1]}
	if m.hosts[k] == nil {
		m.hosts[k] = &index.Fill{Day: k[0], Format: format, Host: k[2]}
	}
	return m.hosts[k]
}

// takeFills is the fetches by day, format and host counted since the last call,
// and how many of them counted as "(other)".
func (m *meters) takeFills() ([]index.Fill, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]index.Fill, 0, len(m.hosts))
	for _, f := range m.hosts {
		out = append(out, *f)
	}
	folded := m.folded
	m.hosts, m.folded = map[[3]string]*index.Fill{}, 0
	return out, folded
}

var metersDoc = [][3]string{
	{"bits_store_requests_total", "counter", "Requests answered, by binding (\"(none)\": no binding), format, method and status."},
	{"bits_store_request_seconds", "histogram", "How long requests took, by binding and format."},
	{"bits_store_response_bytes_total", "counter", "Bytes answered, by binding and format (a redirect's are few; git's are its packs)."},
	{"bits_store_fills_total", "counter", "Fetches from upstream, by format and result (ok, failed)."},
	{"bits_store_fill_bytes_total", "counter", "Bytes fetched from upstream, by format (git's not counted)."},
	{"bits_store_fills_refused_total", "counter", "Fetches from upstream not started, by format and reason (full, throttled)."},
	{"bits_store_fetches_running", "gauge", "Fetches from upstream running now."},
	{"bits_store_goroutines", "gauge", "Goroutines of the service."},
	{"bits_store_heap_bytes", "gauge", "Bytes of the service's heap in use."},
	{"bits_store_start_seconds", "gauge", "When the service started (Unix time)."},
}

// write appends the meters to a /metrics answer.
func (m *meters) write(b *strings.Builder, running int) {
	lines := map[string][]string{}
	add := func(name, labels string, v string) { lines[name] = append(lines[name], name+labels+" "+v) }
	l2 := func(k [2]string, a, b string) string {
		return "{" + a + "=" + quote(k[0]) + "," + b + "=" + quote(k[1])
	}
	m.mu.Lock()
	for _, k := range slices.SortedFunc(maps.Keys(m.requests), cmp4) {
		add("bits_store_requests_total", fmt.Sprintf("{binding=%s,format=%s,method=%s,code=%s}",
			quote(k[0]), quote(k[1]), quote(k[2]), quote(k[3])), itoa64(m.requests[k]))
	}
	for _, k := range slices.SortedFunc(maps.Keys(m.seconds), cmp2) {
		h, n := m.seconds[k], int64(0)
		for i, c := range h.counts {
			n += c
			le := "+Inf"
			if i < len(requestBuckets) {
				le = strconv.FormatFloat(requestBuckets[i], 'g', -1, 64)
			}
			lines["bits_store_request_seconds"] = append(lines["bits_store_request_seconds"],
				"bits_store_request_seconds_bucket"+l2(k, "binding", "format")+",le="+quote(le)+"} "+itoa64(n))
		}
		lines["bits_store_request_seconds"] = append(lines["bits_store_request_seconds"],
			"bits_store_request_seconds_sum"+l2(k, "binding", "format")+"} "+strconv.FormatFloat(h.sum, 'g', -1, 64),
			"bits_store_request_seconds_count"+l2(k, "binding", "format")+"} "+itoa64(n))
		add("bits_store_response_bytes_total", l2(k, "binding", "format")+"}", itoa64(m.bytes[k]))
	}
	for _, k := range slices.SortedFunc(maps.Keys(m.fills), cmp2) {
		add("bits_store_fills_total", l2(k, "format", "result")+"}", itoa64(m.fills[k]))
	}
	for _, f := range slices.Sorted(maps.Keys(m.fillBytes)) {
		add("bits_store_fill_bytes_total", "{format="+quote(f)+"}", itoa64(m.fillBytes[f]))
	}
	for _, k := range slices.SortedFunc(maps.Keys(m.refused), cmp2) {
		add("bits_store_fills_refused_total", l2(k, "format", "reason")+"}", itoa64(m.refused[k]))
	}
	start := m.start
	m.mu.Unlock()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	add("bits_store_fetches_running", "", strconv.Itoa(running))
	add("bits_store_goroutines", "", strconv.Itoa(runtime.NumGoroutine()))
	add("bits_store_heap_bytes", "", strconv.FormatUint(ms.HeapInuse, 10))
	add("bits_store_start_seconds", "", itoa64(start.Unix()))
	for _, d := range metersDoc {
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", d[0], d[2], d[0], d[1])
		for _, l := range lines[d[0]] {
			b.WriteString(l + "\n")
		}
	}
}

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

func cmp2(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) }

func cmp4(a, b [4]string) int {
	return strings.Compare(strings.Join(a[:], "\x00"), strings.Join(b[:], "\x00"))
}

// meterWriter counts a response's bytes, and holds the binding serve resolved.
type meterWriter struct {
	http.ResponseWriter
	n int64
	b *Binding
}

func (w *meterWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *meterWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter } // for http.ResponseController

func (w *meterWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
