# bits-store

BITS artifact store: one service per site in front of the store's volumes (S3
buckets, disk), serving every group. It checks capability tokens, redirects reads
and writes to presigned URLs, indexes what the store holds and mirrors sources.
Design: bits-services ADR 0004. One static Go binary: `make build`, `make test`.

- [docs/TOKEN.md](docs/TOKEN.md): the store token, with test vectors in
  `testdata/tokens/` (`python3 testdata/tokens/vectors.py check`).
- `bits-store -config config.json`: see `config.example.json`. A binding maps a
  logical prefix to a volume and key prefix; GET and HEAD are redirected to presigned
  URLs (plain URLs for public bindings, which use an anonymous volume, sources aside).
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
  path fetches a missing archive: one fetch per name, streamed into staging and
  promoted, its SHA-256, URL and asker (`fetched-by`) in the metadata; meanwhile `202`
  with `Retry-After`, then `302`. A failure answers `502` (`fetch-failed`, with a
  reason), remembered for 10 minutes or until a reload. Clients percent-encode the
  URL (a raw `+` reads as a space). The binding's `max_size` bounds a fetch (bytes,
  default 32 GiB).
- `tarballs` is bits' package store: `<arch>/<hash>` names the build of that hash,
  kept as bits writes it (key prefix `TARS`: `<arch>/store/<hash[:2]>/<hash>/<pkg>-
  <version>[-<revision>].<arch>.tar.gz`). `GET` or `HEAD <prefix>/<arch>/<hash>`
  redirects to it, its file name in `Bits-Object-Name` (bits-store's `404` if none; of
  several, in old stores, the lowest revision by number, as bits picks). An upload of a
  hash names its file in the start (`"name"`, of the path's architecture), its declared
  SHA-256 kept as `sha256` (`sha256:<hex>`), as bits' own writers keep it; it answers
  `409 exists` when the hash holds a file under any name, which a `HEAD` then names.
  bits-store finds the file by listing that hash's folder (the volume's keys need
  `s3:ListBucket`), the index later; reads remember a hit for 10 minutes, a miss for 30
  seconds. Writers with keys of their own can still add a second file under a hash.
- `manifests` is bits' `MANIFESTS` area: the path is the key, as `blob` (the signed
  common manifests), and `GET <prefix>/rev-index/<arch>/<pkg>/<version>?revisions`
  answers `{revision: hash}` from that version's revision markers
  (`rev-index/<arch>/<pkg>/<version>-<revision>`, each holding a hash): bits-store lists
  them and reads each (at most 1000; beyond, `502`). A marker is written with the usual
  upload, once (`409` when taken). Common manifests replaced in place and markers
  deleted (`bits sign`, `bits compliance`) still need the writer's own keys.
- A public binding on a volume with keys (`sources`, `tarballs`, `manifests`) reads by
  plain URLs (its key prefix public-read) and takes writes from a token allowed to
  `PUT`; one on an anonymous volume only reads. A token with a broad `PUT` pattern
  can therefore write to public areas.
- A `public` sources binding reads without a token, by plain URLs (make its key prefix
  public-read; the volume needs keys, to write). A miss is the bucket's `404`, and bits
  then downloads from the URL itself. Only a token with GET on the path fetches; any
  other token reads as anyone does, a bad one gets `401`. What a fetch brings is then
  public, from `site_hosts` too. A public `tarballs` binding likewise reads by plain
  URLs, its volume's keys listing for it.
- Where a fetch may go (`fetch` in the configuration): http(s) only, no proxy; never
  loopback, link-local or the host's own addresses; the site network (private
  addresses and `site_ranges`) only for the hosts in `site_hosts`; anywhere public
  otherwise. bits-store resolves each host itself and checks every address it
  connects to, redirects included. Domains outside `trusted` have a daily budget per
  token subject and per domain (`untrusted_per_subject`, `untrusted_per_domain`,
  default 100 fetches); a spent one answers `429` until midnight UTC. 16 fetches at
  once, 4 per subject; each buffers one part (16 MiB at the default `max_size`).
  Every fetch is logged with its asker, bytes and time.
- `access_log`: `errors` (the default) logs errors and writes, not hits; `all` every
  request; `none` no request lines. Fetches and failures are logged in any case.
- Writes go through staging; a client never gets a URL for a final key:
  `POST <path>?uploads` with `{"size", "md5" (base64), "sha256" (hex)}` returns a
  presigned `PUT` into `STAGING/<id>` and the headers to send; after the upload,
  `POST <path>?complete=<id>` promotes it with a conditional server-side copy (201,
  also on a retry), or answers 409 if the name exists (first writer wins), 422 if size
  or MD5 differ. Size and MD5 are checked; the SHA-256 is kept as the uploader's
  `declared-sha256` (a tarball's as `sha256`). One presigned PUT takes up to 5 GiB; a
  promote above 5 GiB copies in parts, the upload's id in the object's metadata marking
  it as its own.
- Uploads in parts (up to 1 TiB): `POST <path>?uploads` with `{"size", "sha256",
  "part_size", "part_md5"}` (each part's MD5, base64; parts of 5 MiB to 5 GiB, the last
  shorter, at most 10000) returns `"parts"`, a presigned `PUT` per part signing its
  `Content-MD5`; their URLs live a second per 8 MiB longer than `url_lifetime` (not
  beyond the token). `?complete=<id>` assembles the parts, `409 not-uploaded` while one
  is missing or short (put it, complete again), `422 mismatch` when one differs (start
  over), and promotes as above. A complete keeps its upload while it may run. Parts of
  about 1 GiB keep the answer small. Part ETags must be MD5s: no SSE-KMS or SSE-C on the
  bucket.
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
