#!/usr/bin/env python3
"""Extract an unencrypted (raw or LZFSE) IM4P payload (e.g. DeviceTree.d22ap.im4p)
straight from an IPSW, without the `ipsw` tool:

  im4p-extract.py IPSW MEMBER OUT
  im4p-extract.py restore.ipsw Firmware/all_flash/DeviceTree.d22ap.im4p research/ipsw-x/d22ap.adt

IM4P ::= SEQUENCE { IA5String "IM4P", IA5String type, IA5String description,
                    OCTET STRING payload, [compression info] OPTIONAL }
"""
import os, shutil, subprocess, sys, zipfile


def der(buf, off):
    """Return (tag, content_start, content_end) of the DER element at off."""
    tag, n = buf[off], buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(buf[off:off + k], 'big')
        off += k
    return tag, off, off + n


def im4p_payload(blob):
    tag, start, end = der(blob, 0)
    assert tag == 0x30, 'not a DER SEQUENCE'
    fields, off = [], start
    while off < end:
        t, s, e = der(blob, off)
        fields.append((t, blob[s:e]))
        off = e
    assert fields[0] == (0x16, b'IM4P'), 'not an IM4P'
    kind, payload = fields[1][1].decode(), fields[3][1]
    if payload[:4] == b'bvx2':	# LZFSE: Apple's reference `lzfse` CLI (on Windows via WSL)
        cmd = ['lzfse', '-decode'] if shutil.which('lzfse') else \
            ['wsl.exe', '-d', os.environ.get('SWEET_WSL_DISTRO', 'Ubuntu'), '/usr/local/bin/lzfse', '-decode']
        payload = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE, check=True).stdout
    elif payload[:4] == b'comp':
        raise SystemExit(f'{kind}: LZSS payload, not supported here')
    return kind, payload


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    ipsw, member, out = sys.argv[1:]
    kind, payload = im4p_payload(zipfile.ZipFile(ipsw).read(member))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    open(out, 'wb').write(payload)
    print(f'{member}: type {kind}, {len(payload)} bytes -> {out}')
