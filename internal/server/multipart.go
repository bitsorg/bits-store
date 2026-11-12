// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Uploads in parts (README): the client declares part_size and each part's MD5,
// puts the parts by presigned URLs that sign them, and completes as for one PUT.
const (
	minPart      = 5 << 20 // S3's least, but for the last part
	maxPart      = 5 << 30
	maxParts     = 10000
	maxMultipart = 1 << 40
)

// checkParts validates a declared multipart upload: each part's MD5 in hex, and
// the ETag S3 gives the assembled object (the MD5 of the parts' MD5s, -count).
func checkParts(size, partSize int64, partMD5 []string) (hexes []string, etag string, ok bool) {
	if partSize < minPart || partSize > maxPart || size > maxMultipart {
		return nil, "", false
	}
	n := (size + partSize - 1) / partSize
	if n > maxParts || int64(len(partMD5)) != n {
		return nil, "", false
	}
	all := md5.New()
	for _, p := range partMD5 {
		b, err := base64.StdEncoding.DecodeString(p)
		if err != nil || len(b) != 16 {
			return nil, "", false
		}
		all.Write(b)
		hexes = append(hexes, hex.EncodeToString(b))
	}
	return hexes, fmt.Sprintf("%x-%d", all.Sum(nil), n), true
}

// partSizeOf is the size of part n (from 1) of an upload.
func (u *upload) partSizeOf(n int) int64 {
	return min(u.partSize, u.size-int64(n-1)*u.partSize)
}

// presignParts starts the multipart upload into staging and presigns its parts,
// each with its Content-MD5; the upload is aborted when that fails.
func (s *Server) presignParts(ctx context.Context, u *upload, partMD5 []string, expiry time.Duration) ([]map[string]any, error) {
	st := s.stores[u.volume]
	id, err := st.StartMultipart(ctx, u.staging)
	if err != nil {
		return nil, err
	}
	u.uploadID = id
	parts := make([]map[string]any, len(partMD5))
	for i, sum := range partMD5 {
		loc, err := st.PresignPart(ctx, u.staging, id, i+1, expiry, http.Header{"Content-Md5": {sum}})
		if err != nil {
			actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stepTimeout)
			defer cancel()
			st.AbortMultipart(actx, u.staging, id)
			return nil, err
		}
		parts[i] = map[string]any{"number": i + 1, "url": loc, "headers": map[string]string{"Content-MD5": sum}}
	}
	return parts, nil
}

// assemble completes a multipart upload into staging once all its parts are
// there: 0, or an error code and failMsg message ("" for none).
func (s *Server) assemble(parent context.Context, u *upload, id string) (int, string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), copyTime(u.size))
	defer cancel()
	st := s.stores[u.volume]
	assembled := func() (bool, error) {
		si, ok, err := st.Stat(ctx, u.staging)
		return ok && si.Size == u.size && si.ETag == u.md5Hex, err
	}
	if ok, err := assembled(); err != nil {
		log.Printf("stat %s: %v", u.staging, err)
		return http.StatusBadGateway, ""
	} else if ok {
		return 0, "" // a retry, or a complete at the same time
	}
	have, err := st.ListParts(ctx, u.staging, u.uploadID)
	if err != nil {
		if ok, _ := assembled(); ok {
			return 0, ""
		}
		log.Printf("list parts %s: %v", u.staging, err)
		return http.StatusBadGateway, ""
	}
	byN := map[int]partInfo{}
	for _, p := range have {
		byN[p.N] = p
	}
	parts := make([]partInfo, len(u.partMD5))
	for i, sum := range u.partMD5 {
		p, ok := byN[i+1]
		switch {
		case !ok || p.Size != u.partSizeOf(i+1):
			return http.StatusConflict, "not-uploaded" // the client may put it and complete again
		case p.ETag != sum:
			st.AbortMultipart(ctx, u.staging, u.uploadID)
			s.uploads.remove(id)
			return http.StatusUnprocessableEntity, "mismatch"
		}
		parts[i] = p
	}
	if err := st.CompleteMultipart(ctx, u.staging, u.uploadID, parts); err != nil {
		if ok, _ := assembled(); ok {
			return 0, ""
		}
		log.Printf("complete parts %s: %v", u.staging, err)
		return http.StatusBadGateway, ""
	}
	return 0, ""
}
