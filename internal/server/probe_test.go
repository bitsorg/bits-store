// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// probed waits for the background probe /health started.
func probed(t *testing.T, s *Server) {
	for i := 0; i < 200; i++ {
		s.health.mu.Lock()
		running := s.health.running
		s.health.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the probe did not finish")
}

func TestHealthSaysWhichVolumesFailAndLogsWhyOnce(t *testing.T) {
	s, _, now := setup(t)
	m := newMem()
	s.stores["s3"] = m
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	health := func() (int, string) {
		w := do(s, "GET", "/health", nil)
		return w.Code, w.Body.String()
	}
	if c, _ := health(); c != 200 {
		t.Fatalf("first ask: %d", c) // never waits for the probe it starts
	}
	probed(t, s)
	if c, _ := health(); c != 200 {
		t.Fatalf("volumes answering: %d", c)
	}
	m.mu.Lock()
	m.probeErr = errors.New("InvalidAccessKeyId: The AWS Access Key Id you provided does not exist")
	m.mu.Unlock()
	if c, _ := health(); c != 200 {
		t.Fatalf("within a minute of the last probe: %d, want the last result", c)
	}
	for i := 1; i <= 2; i++ { // two probes, one log line
		now = now.Add(probeEvery)
		s.now = func() time.Time { return now }
		health()
		probed(t, s)
	}
	c, body := health()
	if c != 503 || !strings.Contains(body, "volumes failing: s3") || strings.Contains(body, "InvalidAccessKeyId") {
		t.Fatalf("a failing volume: %d %q, want 503 naming it, the reason only in the log", c, body)
	}
	if n := strings.Count(logged.String(), "InvalidAccessKeyId"); n != 1 {
		t.Fatalf("the reason logged %d times, want once:\n%s", n, logged.String())
	}
	if strings.Contains(logged.String(), "/health") {
		t.Fatal("/health in the access log")
	}
	m.mu.Lock()
	m.probeErr = nil
	m.mu.Unlock()
	now = now.Add(probeEvery)
	health()
	probed(t, s)
	if c, _ := health(); c != 200 || !strings.Contains(logged.String(), `volume "s3": answers again`) {
		t.Fatalf("recovered: %d\n%s", c, logged.String())
	}
}

// fakeS3 answers every request with an S3 error, as Ceph does for bad keys or a
// missing bucket; with 200, an empty listing.
func fakeS3(t *testing.T, status int, code string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		if status == 200 {
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>bits</Name></ListBucketResult>`))
			return
		}
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code + `</Code></Error>`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestCheckLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, _, _ := reloadConfig(t, Binding{Prefix: "/store", Volume: "s3", KeyPrefix: "TARS", Format: "tarballs"})
	for _, tc := range []struct {
		status int
		code   string
	}{{403, "InvalidAccessKeyId"}, {404, "NoSuchBucket"}, {403, "AccessDenied"}} {
		v := c.Volumes["s3"]
		v.Endpoint, v.AllowHTTP = fakeS3(t, tc.status, tc.code), true
		c.Volumes["s3"] = v
		writeConfig(t, path, c)
		if err := CheckConfig(path, false); err != nil {
			t.Fatalf("%s, without probing: %v", tc.code, err)
		}
		err := CheckConfig(path, true)
		if err == nil || !strings.Contains(err.Error(), `volume "s3"`) {
			t.Fatalf("%s: %v, want the volume named", tc.code, err)
		}
	}
}

func TestS3Probe(t *testing.T) {
	ep, bucket := os.Getenv("BITS_STORE_S3IT_ENDPOINT"), os.Getenv("BITS_STORE_S3IT_BUCKET")
	if ep == "" || bucket == "" {
		t.Skip("BITS_STORE_S3IT_ENDPOINT and BITS_STORE_S3IT_BUCKET not set")
	}
	t.Setenv("PROBE_BAD_AK", "not-a-key")
	t.Setenv("PROBE_BAD_SK", "not-a-secret")
	for _, tc := range []struct {
		bucket, ak, sk string
		ok             bool
	}{{bucket, "BITS_STORE_S3IT_ACCESS_KEY", "BITS_STORE_S3IT_SECRET_KEY", true},
		{bucket + "-missing", "BITS_STORE_S3IT_ACCESS_KEY", "BITS_STORE_S3IT_SECRET_KEY", false},
		{bucket, "PROBE_BAD_AK", "PROBE_BAD_SK", false}} {
		st, err := VolumeConf{Endpoint: ep, Bucket: tc.bucket, Region: "us-east-1", AllowHTTP: strings.HasPrefix(ep, "http:"),
			AccessKeyEnv: tc.ak, SecretKeyEnv: tc.sk}.store()
		if err != nil {
			t.Fatal(err)
		}
		err = probeErr(probeAll(context.Background(), map[string]objectStore{"v": st}))
		if (err == nil) != tc.ok {
			t.Fatalf("%s with %s: %v", tc.bucket, tc.ak, err)
		}
	}
}

func TestAStartOrReloadProbesAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, _, _ := reloadConfig(t, Binding{Prefix: "/store", Volume: "s3", KeyPrefix: "TARS", Format: "tarballs"})
	v := c.Volumes["s3"]
	v.Endpoint = fakeS3(t, 404, "NoSuchBucket")
	c.Volumes["s3"] = v
	writeConfig(t, path, c)
	r, _, err := NewReloader(path)
	if err != nil {
		t.Fatal(err)
	}
	probed(t, r.cur.Load())
	if w := do(r.cur.Load(), "GET", "/health", nil); w.Code != 503 {
		t.Fatalf("a start's probe: /health %d, want 503 at the first ask", w.Code)
	}
}
