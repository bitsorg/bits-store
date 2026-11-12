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
- `bits-store -check -config config.json` checks a configuration as a start would
  (the volumes' key variables set). The running service reloads its configuration
  when the file changes (`-reload-every`, 5s); one that fails the checks is logged and
  the running one kept. Changed keys in the environment, or `listen`, need a restart. In a
  container, mount the configuration's directory: a mounted single file does not see
  a file replaced by rename.
- A binding's `format` (`internal/format`) names the objects under its prefix;
  `blob`, the default, uses the path as the key. Formats are compiled in and
  register themselves; each has conformance cases in `format_test.go`.
- `sources` is bits' source cache, `<md5[:2]>/<md5>/<file>` (key prefix
  `SOURCES/cache` as bits writes it): the MD5 of the URL as the recipe spells it, the
  file its last segment. A read with `?url=<that URL>` and a token that may GET the
  path fetches a missing archive: one fetch per name, streamed into staging (its
  SHA-256 and the URL kept in the metadata) and promoted; meanwhile `202` with
  `Retry-After`, then `302`. A failure answers `502` (`fetch-failed`, with a reason)
  and is remembered for 10 minutes. Only http(s) from public addresses, checked on
  each connection, redirects included; no proxy. Not the host's own addresses, nor
  the CIDRs of the top-level `fetch_deny`: a site's own ranges (its internal
  services may have public addresses; a NAT or floating address of the host too). The binding's `max_size` bounds a fetch
  (bytes, default 32 GiB). Clients percent-encode the URL in the query (a raw `+`
  would read as a space). 16 fetches at once, 4 per token subject; each buffers one
  part (16 MiB at the default `max_size`).
- Writes go through staging; a client never gets a URL for a final key:
  `POST <path>?uploads` with `{"size", "md5" (base64), "sha256" (hex)}` returns a
  presigned `PUT` into `STAGING/<id>` and the headers to send; after the upload,
  `POST <path>?complete=<id>` promotes it with a conditional server-side copy (201,
  also on a retry), or answers 409 if the name exists (first writer wins), 422 if size
  or MD5 differ. Size and MD5 are checked; the SHA-256 is kept as the uploader's
  `declared-sha256`. Uploads up to 5 GiB for now (one presigned PUT); a promote above
  5 GiB copies in parts, the upload's id in the object's metadata marking it as its own.
  First-writer-wins needs a single instance (the lease is in memory) and bits-store as
  the bucket's only writer. Give the bucket lifecycle rules expiring `STAGING/` and
  aborting incomplete multipart uploads after a day.
- Container: `make image` builds `bits-store:<version>`, the static binary alone in an
  empty image, as user 65532, listening on 8098 (the default when the configuration
  sets no `listen`). Mount the configuration at `/etc/bits-store/config.json` and give
  the S3 keys in the environment its volumes name; for a site CA, mount it and set
  `SSL_CERT_FILE`. `bits-store -health URL` is its health check; the image checks
  port 8098, so a `listen` on another port needs the health check changed too.
- `go test -run TestS3 ./internal/server` runs reads and writes against a real S3
  endpoint when `BITS_STORE_S3IT_*` is set (see `internal/server/s3_test.go`).
- Clients send paths unencoded: the allowed punctuation (`~+!@=,:`) as is, since a `%`
  is refused. A TLS proxy in front must pass the request target unchanged (nginx
  `proxy_pass` without a URI part); the `__Host-` cookie needs HTTPS.
