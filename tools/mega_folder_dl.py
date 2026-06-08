#!/usr/bin/env python3
"""Download all files from a public MEGA folder link into one local folder.

Pure-Python (urllib + pycryptodome); works on Termux aarch64 (no root).

Usage:
    python mega_folder_dl.py "<mega folder url>" <output_dir>
"""
import base64
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

from Crypto.Cipher import AES
from Crypto.Util import Counter

API = "https://g.api.mega.co.nz/cs"

# MEGA API integer error codes (subset); a negative int response means failure.
_MEGA_ERRORS = {
    -2: "EARGS (bad arguments / malformed link)",
    -3: "EAGAIN (try again)",
    -6: "ETOOMANY (too many requests)",
    -9: "ENOENT (not found — folder removed or wrong key)",
    -11: "EACCESS (access denied)",
    -16: "EBLOCKED (resource blocked)",
}


class MegaError(RuntimeError):
    """A MEGA API call returned an error code."""

    def __init__(self, code):
        self.code = code
        super().__init__("MEGA API error %d: %s" % (code, _MEGA_ERRORS.get(code, "unknown")))


def b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s.replace("-", "+").replace("_", "/"))


def a32_to_bytes(a):
    return struct.pack(">%dI" % len(a), *a)


def bytes_to_a32(b):
    if len(b) % 4:
        b += b"\0" * (4 - len(b) % 4)
    return struct.unpack(">%dI" % (len(b) // 4), b)


_seqno = int(time.time() * 1000) % 0xFFFFFFFF


def api_req(data, folder_id):
    """POST a command to the MEGA folder API, with bounded retries.

    Returns the decoded response element. Raises MegaError on an API error
    code, or the underlying network/decode error after the final attempt.
    """
    global _seqno
    _seqno += 1
    url = "%s?id=%d&n=%s" % (API, _seqno, folder_id)
    req = urllib.request.Request(
        url, data=json.dumps(data).encode(), headers={"Content-Type": "application/json"}
    )
    last_err = None
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                result = json.loads(r.read().decode())
            break
        except (urllib.error.URLError, OSError, ValueError) as e:
            last_err = e
            if attempt == 4:
                raise
            time.sleep(2 ** attempt)
    else:  # pragma: no cover - loop always breaks or raises
        raise last_err

    # A bare negative int (or a list whose first element is one) signals an error.
    if isinstance(result, int):
        raise MegaError(result)
    if isinstance(result, list) and result and isinstance(result[0], int):
        raise MegaError(result[0])
    return result[0] if isinstance(result, list) else result


def decrypt_attr(attr, key):
    data = AES.new(a32_to_bytes(key), AES.MODE_CBC, b"\0" * 16).decrypt(attr).rstrip(b"\0")
    if data[:4] != b"MEGA":
        return {"n": "unknown"}
    return json.loads(data[4:].decode("utf-8", "ignore"))


def derive_key(node, master_key):
    """Return (display_name, file_key, iv) for a node, or raise on bad key data.

    `file_key`/`iv` are None for folders (type 1).
    """
    enc_key = bytes_to_a32(b64url_decode(node["k"].split(":")[1]))
    dec = bytes_to_a32(AES.new(a32_to_bytes(master_key), AES.MODE_ECB).decrypt(a32_to_bytes(enc_key)))
    if node["t"] == 0:
        k = (dec[0] ^ dec[4], dec[1] ^ dec[5], dec[2] ^ dec[6], dec[3] ^ dec[7])
        iv = dec[4:6] + (0, 0)
    else:
        k, iv = dec, None
    name = decrypt_attr(b64url_decode(node["a"]), k).get("n", node["h"])
    return name, k, iv


def parse_link(link):
    """Split a public folder link into (folder_id, master_key)."""
    try:
        frag = link.split("/folder/")[1]
        folder_id, folder_key_b64 = frag.split("#")
    except (IndexError, ValueError):
        raise ValueError("not a public MEGA folder link: %r" % link)
    folder_id = folder_id.split("?")[0]
    return folder_id, bytes_to_a32(b64url_decode(folder_key_b64))


def main(link, outdir):
    folder_id, master_key = parse_link(link)
    nodes = api_req([{"a": "f", "c": 1, "r": 1, "ca": 1}], folder_id)["f"]
    os.makedirs(outdir, exist_ok=True)

    names, files = {}, []
    for n in nodes:
        if n["t"] not in (0, 1):
            continue
        try:
            name, k, iv = derive_key(n, master_key)
        except (KeyError, IndexError, ValueError, struct.error) as e:
            # A node whose key we can't derive: keep a name for path-building,
            # but do NOT enqueue a file we can't decrypt (the old code did, then
            # crashed later on a None IV).
            names[n["h"]] = n["h"]
            print("  WARN: skipping undecryptable node %s: %s" % (n["h"], e), file=sys.stderr)
            continue
        names[n["h"]] = name
        if n["t"] == 0:
            files.append((n, k, iv, n.get("s", 0)))

    def path_of(node):
        parts = [names.get(node["h"], node["h"])]
        p = node.get("p")
        while p and p in names:
            parts.append(names[p])
            parent = next((x for x in nodes if x["h"] == p), None)
            if not parent:
                break
            p = parent.get("p")
        return os.path.join(*reversed(parts))

    print("Found %d files" % len(files))
    for node, k, iv, size in files:
        rel = path_of(node)
        dest = os.path.join(outdir, rel)
        os.makedirs(os.path.dirname(dest) or outdir, exist_ok=True)
        if os.path.exists(dest) and os.path.getsize(dest) == size:
            print("  skip:", rel)
            continue
        try:
            g = api_req([{"a": "g", "g": 1, "n": node["h"]}], folder_id)
        except MegaError as e:
            print("  ERROR url for %s: %s" % (rel, e), file=sys.stderr)
            continue
        if "g" not in g:
            print("  ERROR no download url for %s: %s" % (rel, g), file=sys.stderr)
            continue
        print("  downloading %s (%d bytes)" % (rel, size))
        ctr = Counter.new(128, initial_value=((iv[0] << 96) + (iv[1] << 64)))
        cipher = AES.new(a32_to_bytes(k), AES.MODE_CTR, counter=ctr)
        with urllib.request.urlopen(g["g"], timeout=120) as resp, open(dest, "wb") as f:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                f.write(cipher.decrypt(chunk))
    print("Done.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python mega_folder_dl.py <mega_folder_url> <output_dir>", file=sys.stderr)
        sys.exit(2)
    try:
        main(sys.argv[1], sys.argv[2])
    except (MegaError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
