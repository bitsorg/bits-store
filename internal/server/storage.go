// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// objectStore is what the server needs from a volume. Keys are object keys in
// the volume's bucket.
type objectStore interface {
	// Presign returns a URL for one request; hdr lists headers the URL signs,
	// which the client must then send unchanged.
	Presign(ctx context.Context, method, key string, expiry time.Duration, hdr http.Header) (string, error)
	// Stat returns the object's size and ETag; ok is false when it does not exist.
	Stat(ctx context.Context, key string) (size int64, etag string, ok bool, err error)
	// Copy copies src to dst inside the bucket, only if src still has srcETag,
	// replacing metadata and tags. Callers check dst afterwards: some backends
	// report a failed copy with 200.
	Copy(ctx context.Context, src, srcETag, dst string, meta map[string]string) error
	Remove(ctx context.Context, key string) error
	Anonymous() bool
}

func (v VolumeConf) store() (objectStore, error) {
	u, err := url.Parse(v.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" && u.Path != "/" || !(u.Scheme == "https" || u.Scheme == "http" && v.AllowHTTP) {
		return nil, fmt.Errorf("endpoint: an https://host URL needed (http only with allow_http)")
	}
	if s3utils.CheckValidBucketNameStrict(v.Bucket) != nil || v.Region == "" {
		return nil, fmt.Errorf("a valid bucket and a region needed (the region spares a lookup)")
	}
	if v.AccessKeyEnv == "" && v.SecretKeyEnv == "" {
		return plainStore{strings.TrimSuffix(v.Endpoint, "/"), v.Bucket}, nil
	}
	ak, sk := os.Getenv(v.AccessKeyEnv), os.Getenv(v.SecretKeyEnv)
	if ak == "" || sk == "" {
		return nil, fmt.Errorf("%s or %s is empty", v.AccessKeyEnv, v.SecretKeyEnv)
	}
	c, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4(ak, sk, ""),
		Secure: u.Scheme == "https", Region: v.Region})
	if err != nil {
		return nil, err
	}
	return minioStore{c, v.Bucket}, nil
}

type minioStore struct {
	c      *minio.Client
	bucket string
}

func (m minioStore) Anonymous() bool { return false }

func (m minioStore) Presign(ctx context.Context, method, key string, expiry time.Duration, hdr http.Header) (string, error) {
	u, err := m.c.PresignHeader(ctx, method, m.bucket, key, expiry, nil, hdr)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (m minioStore) Stat(ctx context.Context, key string) (int64, string, bool, error) {
	info, err := m.c.StatObject(ctx, m.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).StatusCode == http.StatusNotFound {
			return 0, "", false, nil
		}
		return 0, "", false, err
	}
	return info.Size, strings.Trim(info.ETag, `"`), true, nil
}

func (m minioStore) Copy(ctx context.Context, src, srcETag, dst string, meta map[string]string) error {
	_, err := m.c.CopyObject(ctx,
		minio.CopyDestOptions{Bucket: m.bucket, Object: dst, ReplaceMetadata: true, UserMetadata: meta, ReplaceTags: true},
		minio.CopySrcOptions{Bucket: m.bucket, Object: src, MatchETag: srcETag})
	return err
}

func (m minioStore) Remove(ctx context.Context, key string) error {
	return m.c.RemoveObject(ctx, m.bucket, key, minio.RemoveObjectOptions{})
}

// plainStore is an anonymous volume: plain URLs to public objects, nothing else.
type plainStore struct{ endpoint, bucket string }

var errAnonymous = errors.New("anonymous volume: reads of public objects only")

func (p plainStore) Anonymous() bool { return true }

func (p plainStore) Presign(_ context.Context, method, key string, _ time.Duration, _ http.Header) (string, error) {
	if method != http.MethodGet && method != http.MethodHead {
		return "", errAnonymous
	}
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		segs[i] = strings.ReplaceAll(url.PathEscape(seg), "+", "%2B") // S3 may read + as space
	}
	return p.endpoint + "/" + url.PathEscape(p.bucket) + "/" + strings.Join(segs, "/"), nil
}

func (plainStore) Stat(context.Context, string) (int64, string, bool, error) {
	return 0, "", false, errAnonymous
}
func (plainStore) Copy(context.Context, string, string, string, map[string]string) error {
	return errAnonymous
}
func (plainStore) Remove(context.Context, string) error { return errAnonymous }
