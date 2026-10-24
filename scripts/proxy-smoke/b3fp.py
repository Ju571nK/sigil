#!/usr/bin/env python3
"""Print the sigil-server certificate fingerprint: blake3 hex of the first
certificate's DER in a PEM file (the value `caller_cert_fingerprint` and
`sigil-server proxy fingerprint --fingerprint` expect).

Pure-Python BLAKE3 (hash mode, 32-byte output), stdlib only. Slow but fine for
certificates. Usage: python3 b3fp.py cert.pem [more.pem ...]
"""

import base64
import re
import sys

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
BLOCK_LEN, CHUNK_LEN = 64, 1024
M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, counter, block_len, flags):
    m = list(block)
    s = list(cv) + list(IV[:4]) + [counter & M32, (counter >> 32) & M32, block_len, flags]
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in PERM]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block):
    block = block.ljust(BLOCK_LEN, b"\0")
    return [int.from_bytes(block[i:i + 4], "little") for i in range(0, BLOCK_LEN, 4)]


def _chunk_output(chunk, index):
    """Return (cv, words, counter, block_len, flags) of the chunk's last block."""
    cv = IV
    blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for n, blk in enumerate(blocks):
        flags = (CHUNK_START if n == 0 else 0) | (CHUNK_END if n == len(blocks) - 1 else 0)
        if n == len(blocks) - 1:
            return cv, _words(blk), index, len(blk), flags
        cv = _compress(cv, _words(blk), index, BLOCK_LEN, flags)[:8]
    raise AssertionError("unreachable")


def _cv(out):
    return _compress(*out)[:8]


def _parent(left, right):
    return IV, list(left) + list(right), 0, BLOCK_LEN, PARENT


def blake3(data):
    chunks = [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    stack = []
    for idx, chunk in enumerate(chunks[:-1]):
        cv = _cv(_chunk_output(chunk, idx))
        total = idx + 1
        while total & 1 == 0:
            cv = _cv(_parent(stack.pop(), cv))
            total >>= 1
        stack.append(cv)
    out = _chunk_output(chunks[-1], len(chunks) - 1)
    while stack:
        out = _parent(stack.pop(), _cv(out))
    cv, words, counter, block_len, flags = out
    root = _compress(cv, words, 0, block_len, flags | ROOT)
    return b"".join(w.to_bytes(4, "little") for w in root[:8])


def first_cert_der(pem_text):
    m = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_text, re.S)
    if not m:
        raise ValueError("no certificate in PEM")
    return base64.b64decode("".join(m.group(1).split()), validate=True)


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    for path in argv:
        with open(path) as f:
            print("%s  %s" % (blake3(first_cert_der(f.read())).hex(), path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
