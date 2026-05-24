#!/usr/bin/env python3
"""
generate_backup_keys.py
-----------------------
Vygeneruje RSA-4096 keypair pro šifrování záloh.

Výstup:
  - PRIVATE KEY    → pouze do konzole (nikdy na disk!) — zkopíruj do trezoru
  - public_key.pem → uložen do backup_keys/<název>/
  - encrypt_snippet.py → uložen do backup_keys/<název>/  (vlož do backup skriptu agenta)

Použití:
  python3 generate_backup_keys.py <název>
  python3 generate_backup_keys.py hermes
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json, sys
from pathlib import Path

ENCRYPT_SNIPPET_TEMPLATE = '''\
# encrypt_snippet.py — vlož do svého backup skriptu
# Závislost: pip install cryptography
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json

PUBLIC_KEY_PEM = """{pub_pem}"""


def encrypt_backup(data: bytes) -> bytes:
    """Zašifruje zálohu public klíčem. Dešifrovat lze jen private klíčem."""
    pub = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    ct      = AESGCM(aes_key).encrypt(nonce, data, None)
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return json.dumps({{
        "enc_key": base64.b64encode(enc_key).decode(),
        "nonce":   base64.b64encode(nonce).decode(),
        "ct":      base64.b64encode(ct).decode(),
    }}).encode()
'''


def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key  = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_key, public_key, priv_pem, pub_pem


def verify_roundtrip(private_key, public_key):
    test    = b"backup-roundtrip-test"
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    ct      = AESGCM(aes_key).encrypt(nonce, test, None)
    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    aes_key2 = private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    plain = AESGCM(aes_key2).decrypt(nonce, ct, None)
    assert plain == test, "Roundtrip FAILED!"


def main():
    if len(sys.argv) < 2:
        print("Použití: python3 generate_backup_keys.py <název>")
        print("Příklad: python3 generate_backup_keys.py hermes")
        sys.exit(1)

    name       = sys.argv[1]
    output_dir = Path(__file__).parent / "backup_keys" / name
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"🔑  Generuji RSA-4096 keypair pro '{name}'…")
    private_key, public_key, priv_pem, pub_pem = generate_keypair()

    print("🔄  Ověřuji roundtrip…")
    verify_roundtrip(private_key, public_key)
    print("✅  Roundtrip OK\n")

    # public key + encrypt snippet → na disk
    (output_dir / "public_key.pem").write_text(pub_pem)
    (output_dir / "encrypt_snippet.py").write_text(
        ENCRYPT_SNIPPET_TEMPLATE.format(pub_pem=pub_pem.strip())
    )

    SEP = "═" * 64
    print(SEP)
    print(f"  🔑  PRIVATE KEY — ZKOPÍRUJ DO TREZORU, NIKAM JINAM")
    print(SEP)
    print(priv_pem)
    print(SEP)
    print(f"  📢  public_key.pem    → {output_dir}/public_key.pem")
    print(f"  📦  encrypt_snippet.py → {output_dir}/encrypt_snippet.py")
    print(SEP)
    print()
    print("  Dešifrování záloh:")
    print("  python3 decrypt_backup.py <záloha.enc.json> <výstup> <private_key.pem>")
    print()


if __name__ == "__main__":
    main()
