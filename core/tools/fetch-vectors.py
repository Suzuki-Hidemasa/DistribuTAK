#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""公開ベクトルは配布せず out/ に取り、固定ハッシュを照合する。標準ライブラリだけを使う。"""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[5]
DEST = ROOT / 'out/distributak/vectors'
SOURCES = {
    'noise': ('https://raw.githubusercontent.com/mcginty/snow/8ac60f51cfe3e010c84f0a454cc575ad9204fa12/tests/vectors/cacophony.txt', '3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae'),
    'hpke': ('https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json', '61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6'),
}

def flatten(value, prefix='', result=None):
    if result is None:
        result = {}
    if isinstance(value, dict):
        for k, v in value.items():
            flatten(v, prefix + k + '.', result)
    elif isinstance(value, list):
        result[prefix + 'count'] = str(len(value))
        for i, v in enumerate(value):
            flatten(v, prefix + str(i) + '.', result)
    else:
        result[prefix[:-1]] = str(value)
    return result

def main():
    DEST.mkdir(parents=True, exist_ok=True)
    for name, (url, expected) in SOURCES.items():
        cached = DEST / (name + '.json')
        if not cached.exists():
            data = urllib.request.urlopen(url, timeout=60).read()
        else:
            data = cached.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(name + ': SHA-256 mismatch')
        cached.write_bytes(data)
        values = json.loads(data)
        if name == 'noise':
            selected = [v for v in values['vectors'] if v['protocol_name'] == 'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s']
        else:
            selected = [v for v in values if (v['mode'], v['kem_id'], v['kdf_id'], v['aead_id']) == (0, 32, 1, 1)]
        if len(selected) != 1:
            raise ValueError(name + ': unexpected vector count')
        props = flatten(selected[0])
        (DEST / (name + '.properties')).write_text('\n'.join(k+'='+v for k,v in props.items())+'\n', encoding='ascii')

if __name__ == '__main__':
    main()
