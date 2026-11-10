// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
)

// TestS3 runs reads and writes against a real S3 endpoint, skipped unless
//
//	BITS_STORE_S3IT_ENDPOINT=https://host BITS_STORE_S3IT_BUCKET=b
//	BITS_STORE_S3IT_ACCESS_KEY=... BITS_STORE_S3IT_SECRET_KEY=... [BITS_STORE_S3IT_CREATE=1]
//
// It writes TARS/x86_64-el10-gcc14-opt/ab/h-s3it* and STAGING/ in that bucket.
func TestS3(t *testing.T) {
	ep, bucket := os.Getenv("BITS_STORE_S3IT_ENDPOINT"), os.Getenv("BITS_STORE_S3IT_BUCKET")
	if ep == "" || bucket == "" {
		t.Skip("BITS_STORE_S3IT_ENDPOINT and BITS_STORE_S3IT_BUCKET not set")
	}
	s, tok, _ := setup(t)
	vol := VolumeConf{Endpoint: ep, Bucket: bucket, Region: "us-east-1", AllowHTTP: strings.HasPrefix(ep, "http:"),
		AccessKeyEnv: "BITS_STORE_S3IT_ACCESS_KEY", SecretKeyEnv: "BITS_STORE_S3IT_SECRET_KEY"}
	st, err := vol.store()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if os.Getenv("BITS_STORE_S3IT_CREATE") == "1" {
		if err := st.(minioStore).c.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil &&
			minio.ToErrorResponse(err).Code != "BucketAlreadyOwnedByYou" {
			t.Fatal(err)
		}
	}
	s.stores["s3"] = st
	// the token is checked at the vectors' time; S3 checks the URLs at its own
	data := bytes.Repeat([]byte("bits-store s3 test "), 1000)
	name := final + "-s3it"
	key := finalKey + "-s3it"
	defer st.Remove(ctx, key)
	defer st.Remove(ctx, key+"2")

	w := post(s, name+"?uploads", tok, body(data))
	if w.Code != 201 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var up started
	json.Unmarshal(w.Body.Bytes(), &up)
	put := func(b []byte, md5b64 string) int {
		r, _ := http.NewRequest("PUT", up.URL, bytes.NewReader(b))
		r.Header.Set("Content-MD5", md5b64)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	wrong := md5.Sum([]byte("other"))
	// What the backend itself enforces is reported, not required: promote checks
	// size and ETag either way.
	t.Logf("backend refuses bytes not matching the signed Content-MD5: %v",
		put([]byte("other bytes"), up.Headers["Content-MD5"]) != 200)
	t.Logf("backend refuses a Content-MD5 other than the signed one: %v",
		put(data, base64.StdEncoding.EncodeToString(wrong[:])) != 200)
	if c := put(data, up.Headers["Content-MD5"]); c != 200 {
		t.Fatalf("upload: %d", c)
	}
	if w := post(s, name+"?complete="+up.ID, tok, ""); w.Code != 201 {
		t.Fatalf("complete: %d %s", w.Code, w.Body)
	}
	if _, _, ok, _ := st.Stat(ctx, "STAGING/"+up.ID); ok {
		t.Errorf("staging object left behind")
	}
	// A replay can only re-create the staging object (an orphan for the bucket's
	// lifecycle rule); the final object must be unchanged.
	if put([]byte("replayed"), up.Headers["Content-MD5"]) == 200 {
		t.Log("backend accepted a replay of the staging URL")
		st.Remove(ctx, "STAGING/"+up.ID)
	}
	w = do(s, "GET", name, map[string]string{"Authorization": "Bearer " + tok})
	resp, err := http.Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(got, data) {
		t.Fatalf("read back: %d, %d bytes", resp.StatusCode, len(got))
	}
	info, err := st.(minioStore).c.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	if err != nil || info.UserMetadata["Declared-Sha256"] == "" {
		t.Errorf("no sha256 in the object's metadata: %v %v", info.UserMetadata, err)
	}
	// wrong bytes reach staging only if the backend skips Content-MD5; promote refuses them
	w = post(s, name+"2?uploads", tok, body(data))
	json.Unmarshal(w.Body.Bytes(), &up)
	if put([]byte("x"+string(data[1:])), up.Headers["Content-MD5"]) == 200 {
		if w := post(s, name+"2?complete="+up.ID, tok, ""); w.Code != 422 {
			t.Errorf("wrong bytes promoted: %d", w.Code)
		}
	}
	err = st.Copy(ctx, key, "00000000000000000000000000000000", key+"-copy", nil)
	t.Logf("backend refuses a copy whose source ETag does not match: %v", err != nil)
	st.Remove(ctx, key+"-copy")
	if w := post(s, name+"?uploads", tok, body(data)); w.Code != 409 {
		t.Errorf("start over the existing object: %d", w.Code)
	}
}
