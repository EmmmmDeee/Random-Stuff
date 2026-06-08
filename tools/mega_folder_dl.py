#!/usr/bin/env python3
"""Download all files from a public MEGA folder link into one local folder.
Pure-Python (urllib + pycryptodome). Works on Termux aarch64 (no root).
Usage: python mega_folder_dl.py "<mega folder url>" <output_dir>
"""
import sys, os, json, struct, base64, time
import urllib.request
from Crypto.Cipher import AES
from Crypto.Util import Counter

API = "https://g.api.mega.co.nz/cs"

def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s.replace('-', '+').replace('_', '/'))

def a32_to_bytes(a): return struct.pack('>%dI' % len(a), *a)
def bytes_to_a32(b):
    if len(b) % 4: b += b'\0' * (4 - len(b) % 4)
    return struct.unpack('>%dI' % (len(b) // 4), b)

_seqno = int(time.time() * 1000) % 0xFFFFFFFF
def api_req(data, folder_id):
    global _seqno
    _seqno += 1
    url = "%s?id=%d&n=%s" % (API, _seqno, folder_id)
    req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                 headers={'Content-Type': 'application/json'})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode())
        except Exception:
            if attempt == 4: raise
            time.sleep(2 ** attempt)

def decrypt_attr(attr, key):
    data = AES.new(a32_to_bytes(key), AES.MODE_CBC, b'\0' * 16).decrypt(attr).rstrip(b'\0')
    if data[:4] != b'MEGA': return {'n': 'unknown'}
    return json.loads(data[4:].decode('utf-8', 'ignore'))

def main(link, outdir):
    frag = link.split('/folder/')[1]
    folder_id, folder_key_b64 = frag.split('#')
    folder_id = folder_id.split('?')[0]
    master_key = bytes_to_a32(b64url_decode(folder_key_b64))
    nodes = api_req([{"a": "f", "c": 1, "r": 1, "ca": 1}], folder_id)[0]['f']
    os.makedirs(outdir, exist_ok=True)
    names, files = {}, []
    for n in nodes:
        if n['t'] in (0, 1):
            try:
                enc_key = bytes_to_a32(b64url_decode(n['k'].split(':')[1]))
                dec = bytes_to_a32(AES.new(a32_to_bytes(master_key), AES.MODE_ECB).decrypt(a32_to_bytes(enc_key)))
                if n['t'] == 0:
                    k = (dec[0]^dec[4], dec[1]^dec[5], dec[2]^dec[6], dec[3]^dec[7])
                    iv = dec[4:6] + (0, 0)
                else:
                    k = dec; iv = None
                name = decrypt_attr(b64url_decode(n['a']), k).get('n', n['h'])
            except Exception:
                name, k, iv = n['h'], None, None
            names[n['h']] = name
            if n['t'] == 0: files.append((n, k, iv, n.get('s', 0)))
    def path_of(node):
        parts = [names.get(node['h'], node['h'])]; p = node.get('p')
        while p and p in names:
            parts.append(names[p])
            parent = next((x for x in nodes if x['h'] == p), None)
            if not parent: break
            p = parent.get('p')
        return os.path.join(*reversed(parts))
    print("Found %d files" % len(files))
    for node, k, iv, size in files:
        dest = os.path.join(outdir, path_of(node))
        os.makedirs(os.path.dirname(dest) or outdir, exist_ok=True)
        if os.path.exists(dest) and os.path.getsize(dest) == size:
            print("  skip:", path_of(node)); continue
        g = api_req([{"a": "g", "g": 1, "n": node['h']}], folder_id)[0]
        if 'g' not in g: print("  ERROR url:", path_of(node), g); continue
        print("  downloading %s (%d bytes)" % (path_of(node), size))
        ctr = Counter.new(128, initial_value=((iv[0] << 96) + (iv[1] << 64)))
        cipher = AES.new(a32_to_bytes(k), AES.MODE_CTR, counter=ctr)
        with urllib.request.urlopen(g['g'], timeout=120) as resp, open(dest, 'wb') as f:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk: break
                f.write(cipher.decrypt(chunk))
    print("Done.")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("usage: python mega_folder_dl.py <mega_folder_url> <output_dir>"); sys.exit(1)
    main(sys.argv[1], sys.argv[2])
