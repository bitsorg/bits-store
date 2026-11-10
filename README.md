# bits-store

BITS artifact store: one service per site in front of the store's volumes (S3
buckets, disk), serving every group. It checks capability tokens, redirects reads
and writes to presigned URLs, indexes what the store holds and mirrors sources.
Design: bits-services ADR 0004. One static Go binary: `make build`, `make test`.

- [docs/TOKEN.md](docs/TOKEN.md): the store token, with test vectors in
  `testdata/tokens/` (`python3 testdata/tokens/vectors.py check`).
- `bits-store -config config.json`: see `config.example.json`. A binding maps a
  logical prefix to a volume and key prefix; GET and HEAD are redirected to presigned
  URLs (plain URLs for public bindings, which must use an anonymous volume). Writes
  come next.
- Clients send paths unencoded: the allowed punctuation (`~+!@=,:`) as is, since a `%`
  is refused. A TLS proxy in front must pass the request target unchanged (nginx
  `proxy_pass` without a URI part); the `__Host-` cookie needs HTTPS.
