#!/usr/bin/env python3
"""
decrypt_backup.py — univerzální dešifrovač záloh (RSA-4096 + AES-256-GCM)

Použití:
  python3 decrypt_backup.py <záloha.enc.json> <výstup> <private_key.pem>

Příklad:
  python3 decrypt_backup.py hermes_2026-05-24.enc.json obnova.tar.gz private_key.pem

Závislost: pip install cryptography
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys, base64, json
from pathlib import Path


def decrypt_backup(enc_path: str, out_path: str, key_path: str) -> None:
    priv = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    p    = json.loads(Path(enc_path).read_bytes())

    aes_key = priv.decrypt(
        base64.b64decode(p["enc_key"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    data = AESGCM(aes_key).decrypt(
        base64.b64decode(p["nonce"]),
        base64.b64decode(p["ct"]),
        None,
    )
    Path(out_path).write_bytes(data)
    print(f"✅  Dešifrováno → {out_path}  ({len(data):,} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    decrypt_backup(sys.argv[1], sys.argv[2], sys.argv[3])
