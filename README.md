# bits-store

BITS artifact store: one service per site in front of the store's volumes (S3
buckets, disk), serving every group. It checks capability tokens, redirects reads
and writes to presigned URLs, indexes what the store holds and mirrors sources.
Design: bits-services ADR 0004. One static Go binary: `make build`, `make test`.

- [docs/TOKEN.md](docs/TOKEN.md): the store token, with test vectors in
  `testdata/tokens/` (`python3 testdata/tokens/vectors.py check`).
- `bits-store -config config.json`: see `config.example.json`. A binding maps a
  logical prefix to a volume and key prefix; GET and HEAD are redirected to presigned
  URLs (plain URLs for public bindings, which must use an anonymous volume).
- A binding's `format` (`internal/format`) names the objects under its prefix;
  `blob`, the default, uses the path as the key. Formats are compiled in and
  register themselves; each has conformance cases in `format_test.go`.
- Writes go through staging; a client never gets a URL for a final key:
  `POST <path>?uploads` with `{"size", "md5" (base64), "sha256" (hex)}` returns a
  presigned `PUT` into `STAGING/<id>` and the headers to send; after the upload,
  `POST <path>?complete=<id>` promotes it with a conditional server-side copy (201,
  also on a retry), or answers 409 if the name exists (first writer wins), 422 if size
  or MD5 differ. Size and MD5 are checked; the SHA-256 is kept as the uploader's
  `declared-sha256`. Up to 5 GiB for now. First-writer-wins needs a single instance
  (the lease is in memory) and bits-store as the bucket's only writer. Give the bucket
  a lifecycle rule expiring `STAGING/` after a day.
- `go test -run TestS3 ./internal/server` runs reads and writes against a real S3
  endpoint when `BITS_STORE_S3IT_*` is set (see `internal/server/s3_test.go`).
- Clients send paths unencoded: the allowed punctuation (`~+!@=,:`) as is, since a `%`
  is refused. A TLS proxy in front must pass the request target unchanged (nginx
  `proxy_pass` without a URI part); the `__Host-` cookie needs HTTPS.
