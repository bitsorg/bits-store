#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Make and check the store token test vectors (docs/TOKEN.md).

  vectors.py gen    write vectors.json (needs PyJWT and cryptography)
  vectors.py check  check every case with the reference verifier below
The keys are derived from fixed strings: test only, never for a real site.
"""
import base64, hashlib, hmac, json, re, sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

HERE = Path(__file__).parent
ISS, AUD, NOW = "https://bits.example.org", "example-site/store", 1800000000
LEEWAY, MAX_LIFE, MAX_LEN, TYP = 60, 7 * 86400, 4000, "bits-store+jwt"
HDR = {"alg": "EdDSA", "typ": TYP, "kid": "test-1"}
P = "/sources/archives/x"          # a path the default token may GET


def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def key(name): return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(name.encode()).digest())
def raw_pub(k): return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign_raw(header_json, payload_json, k, enc="utf-8"):
    payload = payload_json if isinstance(payload_json, bytes) else payload_json.encode(enc)
    si = b64(header_json.encode()) + "." + b64(payload)
    return si + "." + b64(k.sign(si.encode()))


def sign(header, claims, k): return sign_raw(json.dumps(header), json.dumps(claims), k)


def claims(**over):
    c = {"iss": ISS, "aud": AUD, "sub": "alice", "grp": "lhcb", "iat": NOW - 600,
         "exp": NOW + 3600, "jti": "t-1",
         "cap": [{"m": "GET", "p": "/store/lhcb/x86_64-el10*/**"},
                 {"m": "GET", "p": "/sources/archives/*"},
                 {"m": "PUT", "p": "/store/lhcb/x86_64-el10-gcc14-opt/**"}]}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def gen():
    import jwt  # PyJWT: the library console-backend signs with
    k1, k2, kb = key("bits-store test key 1"), key("bits-store test key 2"), key("bits-store test build key")
    good = jwt.encode(claims(), k1, algorithm="EdDSA", headers={"kid": "test-1", "typ": TYP})
    h, p, s = good.split(".")
    T = lambda **c: sign(HDR, claims(**c), k1)
    H = lambda **m: sign({k: v for k, v in dict(HDR, **m).items() if v is not None}, claims(), k1)
    C = lambda *cap: T(cap=list(cap))
    tampered = h + "." + b64(json.dumps(claims(cap=[{"m": "GET", "p": "/store/atlas/**"}])).encode()) + "." + s
    hs_in = b64(json.dumps({"alg": "HS256", "typ": TYP, "kid": "test-1"}).encode()) + "." + p
    hs256 = hs_in + "." + b64(hmac.new(raw_pub(k1), hs_in.encode(), "sha256").digest())
    # flip an unused low bit of the signature's last character (64 bytes: 4 spare bits)
    noncanon = good[:-1] + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".index(good[-1]) ^ 1]
    pj = json.dumps(claims())
    dup = sign_raw(json.dumps(HDR), pj[:-1] + ', "cap": [{"m": "GET", "p": "/**"}]}', k1)
    casevar = sign_raw(json.dumps(HDR), pj[:-1] + ', "CAP": [{"m": "GET", "p": "/**"}]}', k1)
    # the longest token within MAX_LEN and the shortest beyond it (base64 skips some lengths)
    toks = [T(jti="j" * n) for n in range(2000, 3200)]
    exact = max((t for t in toks if len(t) <= MAX_LEN), key=len)
    over = min((t for t in toks if len(t) > MAX_LEN), key=len)
    assert len(exact) >= MAX_LEN - 1 and len(over) <= MAX_LEN + 2, (len(exact), len(over))
    G, R = "GET", "/store/lhcb/x86_64-el10-gcc14-opt/ab/0123abcd"
    cases = [
        # allow
        ("get-star-and-doublestar", good, G, R, "allow"),
        ("head-allowed-by-get", good, "HEAD", "/sources/archives/root-6.32.tar.gz", "allow"),
        ("star-matches-empty", good, G, "/store/lhcb/x86_64-el10/ab", "allow"),
        ("put-allowed", good, "PUT", R, "allow"),
        ("allowed-punctuation", C({"m": G, "p": "/a/~+!@=,:._-"}), G, "/a/~+!@=,:._-", "allow"),
        ("exp-at-leeway-edge", T(exp=NOW - 60), G, P, "allow"),
        ("iat-at-leeway-edge", T(iat=NOW + 60, exp=NOW + 3600), G, P, "allow"),
        ("max-lifetime-exact", T(iat=NOW - 600, exp=NOW - 600 + MAX_LIFE), G, P, "allow"),
        ("unknown-claim-ignored", T(note={"a": 1}), G, P, "allow"),
        ("unknown-claim-huge-number", sign_raw(json.dumps(HDR), pj[:-1] + ', "x": 1e400, "y": ' + "9" * 400 + '}', k1), G, P, "allow"),
        ("build-key-build-sub", sign(dict(HDR, kid="build-1"), claims(sub="build:123"), kb), G, P, "allow"),
        ("segment-255", C({"m": G, "p": "/s/" + "x" * 255}), G, "/s/" + "x" * 255, "allow"),
        ("max-length", exact, G, P, "allow"),
        ("four-stars", C({"m": G, "p": "/s/*a*b*c*"}), G, "/s/xaybzc", "allow"),
        # deny
        ("other-group", good, G, "/store/atlas/x86_64-el10-gcc14-opt/ab/0123abcd", "deny"),
        ("put-needs-put", good, "PUT", "/store/lhcb/x86_64-el10-gcc15-opt/ab/0123abcd", "deny"),
        ("get-not-implied-by-put", C({"m": "PUT", "p": "/store/lhcb/**"}), G, "/store/lhcb/a", "deny"),
        ("head-not-implied-by-put", C({"m": "PUT", "p": "/store/lhcb/**"}), "HEAD", "/store/lhcb/a", "deny"),
        ("doublestar-needs-a-segment", good, G, "/store/lhcb/x86_64-el10-gcc14-opt", "deny"),
        ("star-stays-in-segment", good, G, "/sources/archives/a/b", "deny"),
        ("method-not-granted", good, "DELETE", P, "deny"),
        ("case-sensitive-match", good, G, "/Sources/archives/x", "deny"),
        ("grp-grants-nothing", T(grp="atlas"), G, "/store/atlas/x86_64-el10/a", "deny"),
        # bad-path (checked before the token)
        ("bad-path-before-token", "not-a-token", G, "/a/../b", "bad-path"),
        ("dotdot", good, G, "/store/lhcb/x86_64-el10-gcc14-opt/../../atlas/x", "bad-path"),
        ("dot", good, G, "/sources/./archives/x", "bad-path"),
        ("percent", good, G, "/sources/archives/a%20b", "bad-path"),
        ("encoded-slash", good, G, "/sources/archives/a%2Fb", "bad-path"),
        ("space", good, G, "/sources/archives/a b", "bad-path"),
        ("backslash", good, G, "/sources/archives/a\\b", "bad-path"),
        ("star-in-request", good, G, "/sources/archives/*", "bad-path"),
        ("non-ascii", good, G, "/sources/archives/é", "bad-path"),
        ("fullwidth-dots", good, G, "/sources/．．/x", "bad-path"),
        ("control-char", good, G, "/sources/archives/a\nb", "bad-path"),
        ("trailing-slash", good, G, "/sources/archives/x/", "bad-path"),
        ("double-slash", good, G, "/sources//archives/x", "bad-path"),
        ("root", good, G, "/", "bad-path"),
        ("relative", good, G, "sources/archives/x", "bad-path"),
        ("segment-too-long", good, G, "/sources/archives/" + "x" * 256, "bad-path"),
        # invalid: format and signature
        ("no-token", "", G, P, "invalid"),
        ("tampered-payload", tampered, G, "/store/atlas/x86_64-el10-gcc14-opt/ab/x", "invalid"),
        ("other-key-same-kid", sign(HDR, claims(), k2), G, P, "invalid"),
        ("unknown-kid", H(kid="test-9"), G, P, "invalid"),
        ("alg-hs256-with-public-key", hs256, G, P, "invalid"),
        ("alg-none", b64(json.dumps({"alg": "none", "typ": TYP, "kid": "test-1"}).encode()) + "." + p + ".", G, P, "invalid"),
        ("typ-jwt", H(typ="JWT"), G, P, "invalid"),
        ("typ-missing", H(typ=None), G, P, "invalid"),
        ("kid-case-sensitive", H(kid="Test-1"), G, P, "invalid"),
        ("header-duplicate-kid", sign_raw('{"alg": "EdDSA", "typ": "%s", "kid": "test-9", "kid": "test-1"}' % TYP, pj, k1), G, P, "invalid"),
        ("header-case-variant", sign_raw('{"Alg": "EdDSA", "alg": "EdDSA", "typ": "%s", "kid": "test-1"}' % TYP, pj, k1), G, P, "invalid"),
        ("header-kelvin-name", sign_raw('{"alg": "EdDSA", "typ": "%s", "kid": "test-1", "\u212aid": "test-9"}' % TYP, pj, k1), G, P, "invalid"),
        ("payload-utf16", sign_raw(json.dumps(HDR), pj, k1, enc="utf-16"), G, P, "invalid"),
        ("build-key-user-sub", sign(dict(HDR, kid="build-1"), claims(), kb), G, P, "invalid"),
        ("user-key-build-sub", T(sub="build:123"), G, P, "invalid"),
        ("header-jwk", H(jwk={"kty": "OKP"}), G, P, "invalid"),
        ("header-cty", H(cty="JWT"), G, P, "invalid"),
        ("header-not-object", sign_raw("[]", pj, k1), G, P, "invalid"),
        ("padded", good + "==", G, P, "invalid"),
        ("non-canonical-base64", noncanon, G, P, "invalid"),
        ("trailing-newline", good + "\n", G, P, "invalid"),
        ("five-parts", good + ".x.y", G, P, "invalid"),
        ("empty-signature", h + "." + p + ".", G, P, "invalid"),
        ("too-long", over, G, P, "invalid"),
        # invalid: claims
        ("expired", T(exp=NOW - 61), G, P, "invalid"),
        ("issued-in-future", T(iat=NOW + 61, exp=NOW + 3600), G, P, "invalid"),
        ("exp-not-after-iat", T(iat=NOW, exp=NOW), G, P, "invalid"),
        ("lifetime-too-long", T(iat=NOW - 600, exp=NOW - 600 + MAX_LIFE + 1), G, P, "invalid"),
        ("exp-float", T(exp=float(NOW + 3600)), G, P, "invalid"),
        ("exp-bool", T(exp=True), G, P, "invalid"),
        ("exp-huge", T(exp=2 ** 70), G, P, "invalid"),
        ("iat-negative", T(iat=-1), G, P, "invalid"),
        ("iat-min-int64", T(iat=-2 ** 63), G, P, "invalid"),
        ("exp-exponent", sign_raw(json.dumps(HDR), pj.replace('"exp": %d' % (NOW + 3600), '"exp": 1.8000036e9'), k1), G, P, "invalid"),
        ("non-ascii-unknown-claim", sign_raw(json.dumps(HDR), pj[:-1] + ', "\u00e9": 1}', k1), G, P, "invalid"),
        ("payload-invalid-utf8", sign_raw(json.dumps(HDR), pj.replace('"alice"', '"alice\\xff"').encode().replace(b"\\xff", b"\xff"), k1), G, P, "invalid"),
        ("nan-claim", sign_raw(json.dumps(HDR), pj[:-1] + ', "x": NaN}', k1), G, P, "invalid"),
        ("long-s-claim", sign_raw(json.dumps(HDR), pj[:-1] + ', "\u017fub": "build:1"}', k1), G, P, "invalid"),
        ("nbf-present", T(nbf=NOW - 600), G, P, "invalid"),
        ("wrong-audience", T(aud="other-site/store"), G, P, "invalid"),
        ("audience-list", T(aud=[AUD]), G, P, "invalid"),
        ("wrong-issuer", T(iss="https://evil.example.org"), G, P, "invalid"),
    ] + [("missing-" + n, T(**{n: None}), G, P, "invalid")
         for n in ("iss", "aud", "sub", "grp", "iat", "exp", "jti", "cap")] + [
        ("duplicate-claim", dup, G, "/store/atlas/x", "invalid"),
        ("case-variant-claim", casevar, G, "/store/atlas/x", "invalid"),
        # invalid: capabilities
        ("empty-cap", T(cap=[]), G, P, "invalid"),
        ("cap-not-list", T(cap={"m": G, "p": "/**"}), G, P, "invalid"),
        ("cap-entry-not-object", C("GET /**"), G, P, "invalid"),
        ("method-lowercase", C({"m": "get", "p": "/sources/**"}), G, P, "invalid"),
        ("method-head", C({"m": "HEAD", "p": "/sources/**"}), G, P, "invalid"),
        ("unknown-method-in-cap", C({"m": "DELETE", "p": "/x/**"}, {"m": G, "p": "/sources/**"}), G, P, "invalid"),
        ("extra-member-in-cap", C({"m": G, "p": "/sources/**", "c": 1}), G, P, "invalid"),
        ("case-variant-in-cap", C({"m": G, "p": "/x", "P": "/**"}), G, P, "invalid"),
        ("cap-duplicate-m", sign_raw(json.dumps(HDR), pj.replace('{"m": "PUT", "p"', '{"m": "PUT", "m": "GET", "p"'), k1), G, "/store/lhcb/x86_64-el10-gcc14-opt/a", "invalid"),
        ("pattern-segment-256", C({"m": G, "p": "/s/" + "x" * 256}), G, P, "invalid"),
        ("missing-p", C({"m": G}), G, P, "invalid"),
        ("p-not-string", C({"m": G, "p": 1}), G, P, "invalid"),
        ("doublestar-not-last", C({"m": G, "p": "/sources/**/x"}), G, P, "invalid"),
        ("doublestar-in-segment", C({"m": G, "p": "/sources/a**"}), G, "/sources/ab", "invalid"),
        ("triple-star", C({"m": G, "p": "/sources/***"}), G, P, "invalid"),
        ("five-stars", C({"m": G, "p": "/s/*a*b*c*d*"}), G, "/s/abcd", "invalid"),
        ("bracket-not-allowed", C({"m": G, "p": "/sources/archives/[x]"}), G, P, "invalid"),
        ("percent-in-pattern", C({"m": G, "p": "/sources/a%20b"}), G, P, "invalid"),
        ("dotdot-in-pattern", C({"m": G, "p": "/sources/../**"}), G, P, "invalid"),
        ("root-pattern", C({"m": G, "p": "/"}), G, P, "invalid"),
    ]
    names = [c[0] for c in cases]
    assert len(names) == len(set(names))
    out = {"comment": "Generated by vectors.py gen; test keys only. See docs/TOKEN.md.",
           "issuer": ISS, "audience": AUD, "now": NOW, "max_lifetime": MAX_LIFE,
           "keys": {"test-1": {"x": b64(raw_pub(k1)), "signer": "user"},
                    "build-1": {"x": b64(raw_pub(kb)), "signer": "build"}},
           "cases": [dict(zip(("name", "token", "method", "path", "outcome"), c)) for c in cases]}
    (HERE / "vectors.json").write_text(json.dumps(out, indent=1) + "\n")
    print("wrote %d cases" % len(cases))


# Reference verifier: an independent reading of docs/TOKEN.md.
SEG = re.compile(r"[A-Za-z0-9._~+!@=,:-]{1,255}")
PSEG = re.compile(r"[A-Za-z0-9._~+!@=,:*-]{1,255}")
KNOWN = {"alg", "typ", "kid", "iss", "aud", "sub", "grp", "iat", "exp", "jti", "cap", "nbf", "m", "p"}
KNOWN_LOWER = {n.lower(): n for n in KNOWN}


class Bad(Exception):
    pass


def segments(path, seg_re):
    if not path.startswith("/"):
        raise Bad("relative")
    segs = path[1:].split("/")
    for s in segs:
        if not seg_re.fullmatch(s) or s in (".", ".."):
            raise Bad("segment")
    return segs


def pattern(p):
    segs = segments(p, PSEG)
    for i, s in enumerate(segs):
        if s == "**" and i == len(segs) - 1:
            continue
        if "**" in s or s.count("*") > 4:
            raise Bad("stars")
    return segs


def seg_match(pat, s):
    # linear glob: '*' matches any run; backtrack only to the last '*'
    i = j = 0
    star, mark = -1, 0
    while j < len(s):
        if i < len(pat) and pat[i] != "*" and pat[i] == s[j]:
            i += 1; j += 1
        elif i < len(pat) and pat[i] == "*":
            star, mark = i, j; i += 1
        elif star >= 0:
            i, mark = star + 1, mark + 1; j = mark
        else:
            return False
    return all(c == "*" for c in pat[i:])


def path_match(pat, segs):
    if pat[-1] == "**":
        return len(segs) >= len(pat) and all(map(seg_match, pat[:-1], segs))
    return len(segs) == len(pat) and all(map(seg_match, pat, segs))


def strict_object(pairs):
    names = [n for n, _ in pairs]
    if not all(n.isascii() for n in names):
        raise Bad("non-ASCII member name")
    if len(names) != len(set(names)):
        raise Bad("duplicate member")
    for n in names:
        if n.lower() in KNOWN_LOWER and n != KNOWN_LOWER[n.lower()]:
            raise Bad("case variant")
    return dict(pairs)


def no_constant(name):
    raise Bad("not JSON: " + name)  # NaN, Infinity


def unb64(s):
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        raise Bad("base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64(b) != s:
        raise Bad("non-canonical")
    return b


def time_int(v):
    if type(v) is not int or not 0 <= v < 2 ** 53:
        raise Bad("time")
    return v


def verify(token, v):
    if not token or len(token) > MAX_LEN or not re.fullmatch(r"[A-Za-z0-9_.-]+", token) \
            or token.count(".") != 2:
        raise Bad("form")
    h, p, s = token.split(".")
    load = lambda x: json.loads(unb64(x).decode("utf-8"), object_pairs_hook=strict_object,
                                parse_constant=no_constant)
    header = load(h)
    if not isinstance(header, dict) or set(header) != {"alg", "typ", "kid"} \
            or header["alg"] != "EdDSA" or header["typ"] != TYP:
        raise Bad("header")
    kid = header["kid"]
    if not isinstance(kid, str) or kid not in v["keys"]:
        raise Bad("kid")
    try:
        Ed25519PublicKey.from_public_bytes(unb64(v["keys"][kid]["x"])).verify(unb64(s), (h + "." + p).encode())
    except InvalidSignature:
        raise Bad("signature")
    c = load(p)
    if not isinstance(c, dict) or "nbf" in c:
        raise Bad("claims")
    for n in ("iss", "aud", "sub", "grp", "jti"):
        if not isinstance(c.get(n), str):
            raise Bad("claim " + n)
    if c["sub"].startswith("build:") != (v["keys"][kid]["signer"] == "build"):
        raise Bad("signer")
    iat, exp, now = time_int(c.get("iat")), time_int(c.get("exp")), v["now"]
    if c["iss"] != v["issuer"] or c["aud"] != v["audience"] or exp <= iat or now > exp + LEEWAY \
            or iat > now + LEEWAY or exp - iat > v["max_lifetime"]:
        raise Bad("claims")
    if not isinstance(c.get("cap"), list) or not c["cap"]:
        raise Bad("cap")
    caps = []
    for e in c["cap"]:
        if not isinstance(e, dict) or set(e) != {"m", "p"} or e["m"] not in ("GET", "PUT") \
                or not isinstance(e["p"], str):
            raise Bad("cap entry")
        caps.append((e["m"], pattern(e["p"])))
    return caps


def outcome(case, v):
    try:
        segs = segments(case["path"], SEG)
    except Bad:
        return "bad-path"
    try:
        caps = verify(case["token"], v)
    except (Bad, ValueError, UnicodeDecodeError):
        return "invalid"
    m = "GET" if case["method"] == "HEAD" else case["method"]
    return "allow" if any(cm == m and path_match(cp, segs) for cm, cp in caps) else "deny"


def check():
    v = json.loads((HERE / "vectors.json").read_text())
    bad = [(c["name"], c["outcome"], outcome(c, v)) for c in v["cases"] if outcome(c, v) != c["outcome"]]
    for name, want, got in bad:
        print("FAIL %s: want %s, got %s" % (name, want, got))
    print("%d cases, %d failed" % (len(v["cases"]), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(gen() if sys.argv[1:] == ["gen"] else check() if sys.argv[1:] == ["check"] else
             print(__doc__) or 2)
