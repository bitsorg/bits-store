// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// A copy above maxCopy goes in parts of copyPart (S3's CopyObject takes up to 5 GiB).
var maxCopy, copyPart int64 = 5 << 30, 1 << 30

// objInfo is what Stat tells of an object; Meta's keys are lower case, without x-amz-meta-.
type objInfo struct {
	Size int64
	ETag string
	Meta map[string]string
}

// partInfo is an uploaded part of a multipart upload; ETag without quotes.
type partInfo struct {
	N    int
	Size int64
	ETag string
}

// objectStore is what the server needs from a volume. Keys are object keys in
// the volume's bucket.
type objectStore interface {
	// Presign returns a URL for one request; hdr lists headers the URL signs,
	// which the client must then send unchanged.
	Presign(ctx context.Context, method, key string, expiry time.Duration, hdr http.Header) (string, error)
	// Stat returns what is known of the object; ok is false when it does not exist.
	Stat(ctx context.Context, key string) (info objInfo, ok bool, err error)
	// Copy copies src (of size bytes) to dst inside the bucket, only if src still
	// has srcETag, replacing metadata and tags. Callers check dst afterwards: some
	// backends report a failed copy with 200.
	Copy(ctx context.Context, src, srcETag, dst string, size int64, meta map[string]string) error
	// A multipart upload to key, whose parts a client puts by presigned URLs.
	StartMultipart(ctx context.Context, key string) (uploadID string, err error)
	PresignPart(ctx context.Context, key, uploadID string, n int, expiry time.Duration, hdr http.Header) (string, error)
	ListParts(ctx context.Context, key, uploadID string) ([]partInfo, error)
	CompleteMultipart(ctx context.Context, key, uploadID string, parts []partInfo) error
	AbortMultipart(ctx context.Context, key, uploadID string) error
	// Put streams r to key, in parts of partSize when longer; meta as Copy's.
	Put(ctx context.Context, key string, r io.Reader, partSize int64, meta map[string]string) error
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

func (m minioStore) Stat(ctx context.Context, key string) (objInfo, bool, error) {
	info, err := m.c.StatObject(ctx, m.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).StatusCode == http.StatusNotFound {
			return objInfo{}, false, nil
		}
		return objInfo{}, false, err
	}
	meta := map[string]string{}
	for k, v := range info.UserMetadata {
		meta[strings.ToLower(k)] = v
	}
	return objInfo{info.Size, strings.Trim(info.ETag, `"`), meta}, true, nil
}

func (m minioStore) Copy(ctx context.Context, src, srcETag, dst string, size int64, meta map[string]string) error {
	d := minio.CopyDestOptions{Bucket: m.bucket, Object: dst, ReplaceMetadata: true, UserMetadata: meta,
		ReplaceTags: true, PartSize: uint64(copyPart)}
	s := minio.CopySrcOptions{Bucket: m.bucket, Object: src, MatchETag: srcETag} // each part's condition too
	var err error
	if size <= maxCopy {
		_, err = m.c.CopyObject(ctx, d, s)
	} else {
		_, err = m.c.ComposeObject(ctx, d, s)
	}
	return err
}

func (m minioStore) Put(ctx context.Context, key string, r io.Reader, partSize int64, meta map[string]string) error {
	_, err := m.c.PutObject(ctx, m.bucket, key, r, -1,
		minio.PutObjectOptions{UserMetadata: meta, PartSize: uint64(partSize)})
	return err
}

func (m minioStore) StartMultipart(ctx context.Context, key string) (string, error) {
	return minio.Core{Client: m.c}.NewMultipartUpload(ctx, m.bucket, key, minio.PutObjectOptions{})
}

func (m minioStore) PresignPart(ctx context.Context, key, uploadID string, n int, expiry time.Duration, hdr http.Header) (string, error) {
	q := url.Values{"partNumber": {fmt.Sprint(n)}, "uploadId": {uploadID}}
	u, err := m.c.PresignHeader(ctx, http.MethodPut, m.bucket, key, expiry, q, hdr)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (m minioStore) ListParts(ctx context.Context, key, uploadID string) ([]partInfo, error) {
	var out []partInfo
	for marker := 0; ; {
		r, err := minio.Core{Client: m.c}.ListObjectParts(ctx, m.bucket, key, uploadID, marker, 1000)
		if err != nil {
			return nil, err
		}
		for _, p := range r.ObjectParts {
			out = append(out, partInfo{p.PartNumber, p.Size, strings.Trim(p.ETag, `"`)})
		}
		if !r.IsTruncated || r.NextPartNumberMarker <= marker {
			return out, nil // a short list is a part missing: 409, never a loop
		}
		marker = r.NextPartNumberMarker
	}
}

func (m minioStore) CompleteMultipart(ctx context.Context, key, uploadID string, parts []partInfo) error {
	cp := make([]minio.CompletePart, len(parts))
	for i, p := range parts {
		cp[i] = minio.CompletePart{PartNumber: p.N, ETag: p.ETag}
	}
	_, err := minio.Core{Client: m.c}.CompleteMultipartUpload(ctx, m.bucket, key, uploadID, cp, minio.PutObjectOptions{})
	return err
}

func (m minioStore) AbortMultipart(ctx context.Context, key, uploadID string) error {
	return minio.Core{Client: m.c}.AbortMultipartUpload(ctx, m.bucket, key, uploadID)
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

func (plainStore) Stat(context.Context, string) (objInfo, bool, error) {
	return objInfo{}, false, errAnonymous
}
func (plainStore) Copy(context.Context, string, string, string, int64, map[string]string) error {
	return errAnonymous
}
func (plainStore) StartMultipart(context.Context, string) (string, error) { return "", errAnonymous }
func (plainStore) PresignPart(context.Context, string, string, int, time.Duration, http.Header) (string, error) {
	return "", errAnonymous
}
func (plainStore) ListParts(context.Context, string, string) ([]partInfo, error) {
	return nil, errAnonymous
}
func (plainStore) CompleteMultipart(context.Context, string, string, []partInfo) error {
	return errAnonymous
}
func (plainStore) AbortMultipart(context.Context, string, string) error { return errAnonymous }
func (plainStore) Put(context.Context, string, io.Reader, int64, map[string]string) error {
	return errAnonymous
}
func (plainStore) Remove(context.Context, string) error { return errAnonymous }
