# bits-store

BITS artifact store: one service per site in front of the store's volumes (S3
buckets, disk), serving every group. It checks capability tokens, redirects reads
and writes to presigned URLs, indexes what the store holds and mirrors sources.
Design: bits-services ADR 0004. One static Go binary (to come).

- [docs/TOKEN.md](docs/TOKEN.md): the store token, with test vectors in
  `testdata/tokens/` (`python3 testdata/tokens/vectors.py check`).
