# Store tokens

A store token says what its holder may read or write in one site's store. The site's
bits-console signs it when a user signs in to a group (a cookie in the browser,
`~/.bits/token` for the CLI); the orchestrator signs one for each build. bits-store
checks it on every request for a non-public object and, for a write, answers with a
presigned URL: no client ever holds storage credentials. Public objects need no token.

Test vectors: `testdata/tokens/vectors.json`, made and checked by
`testdata/tokens/vectors.py`. Every implementation (signer, client, verifier) runs
them in its tests.

## Carrying the token

- `Authorization: Bearer <token>`. Only when the request has no `Authorization`
  header, the cookie `__Host-bits_store_token` (so no sibling host can set it).
- `~/.bits/token` holds the token; the client strips trailing whitespace (`\n`, `\r\n`).
- A request for a non-public object without a token is refused with 401.
- How bits-store answers an allowed request (redirects, presigned URLs, what makes a
  `PUT` create-only) is the API's part, not the token's.

## Encoding

A JWS in compact form: `base64url(header) "." base64url(payload) "." base64url(sig)`.
At most 4000 bytes, so it fits a cookie with its name. Only the characters `A-Z a-z 0-9 - _ .`;
base64url without padding and canonical (unused low bits zero). Anything else,
including a newline, makes the token invalid.

Header, a JSON object with exactly these members:

| Member | Value |
|---|---|
| `alg` | `"EdDSA"` |
| `typ` | `"bits-store+jwt"`, so no other kind of JWT is accepted |
| `kid` | the signing key's id, a string matched exactly |

`sig` is the Ed25519 signature of the ASCII bytes `base64url(header) "." base64url(payload)`
with the key named by `kid`. The verifier is configured with each `kid`'s raw 32-byte
public key and its signer: `user` (bits-console) or `build` (the orchestrator). An
unknown `kid` makes the token invalid. Keys rotate by adding a new `kid`.

## Claims

The payload is a JSON object.

| Claim | Type | Meaning |
|---|---|---|
| `iss` | string | issuer; must equal the verifier's configured issuer |
| `aud` | string | the store's configured audience (a string, not a list) |
| `sub` | string | who, for the audit log: `build:<job>` exactly when the key's signer is `build` |
| `grp` | string | the group signed in to, for the audit log only |
| `iat` | integer | issued at, seconds since the epoch |
| `exp` | integer | expires at, seconds since the epoch |
| `jti` | string | unique id, for the verifier's deny-list |
| `cap` | list | capabilities, at least one: the only claim that grants anything |

All are required. `iat` and `exp` are integers from 0 to 2^53 − 1 (no fraction, no
exponent, not booleans). With 60 seconds of leeway for clocks, the token is invalid
if `exp <= iat`, `now > exp + 60`, `iat > now + 60`, or `exp - iat` exceeds the
verifier's maximum lifetime (configured; default 7 days). A `jti` on the deny-list is
invalid. Other claims are ignored, except `nbf`, which this format does not use: a
token carrying it is invalid.

## Strict JSON

Header and payload are UTF-8 JSON, and members are matched by exact name. A token is
invalid if any object in its header or payload has:

- a member name that is not ASCII;
- a duplicate member;
- a member whose name equals one of `alg typ kid iss aud sub grp iat exp jti cap nbf m p`
  except for ASCII letter case (`CAP`, `Exp`).

Go's `encoding/json` matches names ignoring case, Unicode folding included (`ſ` as
`s`); a Go verifier must check the raw names first. Times are checked within their
range before any arithmetic on them.

## Capabilities

Each entry of `cap` is an object with exactly the members `m` and `p`:

| Member | Value |
|---|---|
| `m` | `"GET"` (also allows `HEAD`) or `"PUT"` (create a new object) |
| `p` | a pattern over logical paths |

An unknown method, a missing or extra member, or a malformed pattern makes the whole
token invalid: a restriction the verifier does not understand must not be dropped.
PUT does not imply GET, nor GET PUT.

## Paths and patterns

A **request path** is the path exactly as sent (the request line, without the query),
never a decoded or cleaned form; the same segments then name the object in the store's
index (where it is kept physically is the store's choice, content-addressed). It is
a bad path unless it is `/` followed by one or more segments separated by `/`, where
every segment:

- has 1 to 255 of the characters `A-Z a-z 0-9 . _ - ~ + ! @ = , :`;
- is not `.` or `..`.

So there is no percent-decoding (a `%` is a bad path), no Unicode, and no empty
segment (`//`, a trailing `/`). Volumes must be case-sensitive.

A **pattern** follows the same rules, plus the character `*`:

- `*` inside a segment matches any run of the allowed characters (possibly none)
  within that one segment: `x86_64-el10*` matches `x86_64-el10-gcc14-opt`. At most 4
  `*` in a segment.
- `**` as the whole last segment matches one or more further segments: `/store/lhcb/**`
  matches `/store/lhcb/a` and `/store/lhcb/a/b`, not `/store/lhcb`.
- `**` anywhere else, or `***`, is malformed. `*` is the only special character.

A request is allowed when the token is valid and some capability has a matching
method and a pattern matching every segment of the path.

## Outcomes

| Outcome | When | HTTP |
|---|---|---|
| `allow` | valid token, a capability matches | |
| `deny` | valid token, no capability matches | 403 |
| `invalid` | no token, or the token is refused | 401 |
| `bad-path` | the request path breaks the rules above | 400 |

The path is checked first, then the token, then the capabilities. In the vectors,
`path` never has a query.
