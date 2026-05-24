#!/usr/bin/env python3
"""
encrypt_backup.py — univerzální šifrovač záloh (RSA-4096 + AES-256-GCM)

Použití:
  python3 encrypt_backup.py <vstup> <výstup.enc.json> <public_key.pem>

Příklad:
  python3 encrypt_backup.py hermes_backup.tar.gz hermes_2026-05-24.enc.json backup_keys/hermes/public_key.pem

Závislost: pip install cryptography
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys, os, base64, json
from pathlib import Path


def encrypt_backup(in_path: str, out_path: str, key_path: str) -> None:
    pub     = serialization.load_pem_public_key(Path(key_path).read_bytes())
    data    = Path(in_path).read_bytes()

    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    ct      = AESGCM(aes_key).encrypt(nonce, data, None)
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    Path(out_path).write_bytes(json.dumps({
        "enc_key": base64.b64encode(enc_key).decode(),
        "nonce":   base64.b64encode(nonce).decode(),
        "ct":      base64.b64encode(ct).decode(),
    }).encode())
    print(f"✅  Zašifrováno → {out_path}  ({len(data):,} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    encrypt_backup(sys.argv[1], sys.argv[2], sys.argv[3])
