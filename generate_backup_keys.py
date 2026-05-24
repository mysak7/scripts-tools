#!/usr/bin/env python3
"""
generate_backup_keys.py
-----------------------
Vygeneruje RSA-4096 keypair a vypíše vše do konzole.
Na disk se NIC neukládá.

Použití:
  python3 generate_backup_keys.py
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def main():
    # Generuj keypair
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

    # Roundtrip test
    test    = b"roundtrip-test"
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    ct      = AESGCM(aes_key).encrypt(nonce, test, None)
    enc_key = public_key.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    aes_key2 = private_key.decrypt(enc_key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    assert AESGCM(aes_key2).decrypt(nonce, ct, None) == test, "Roundtrip FAILED!"

    encrypt_py = f'''\
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json

PUBLIC_KEY_PEM = """{pub_pem.strip()}"""

def encrypt_backup(data: bytes) -> bytes:
    pub     = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    ct      = AESGCM(aes_key).encrypt(nonce, data, None)
    enc_key = pub.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return json.dumps({{
        "enc_key": base64.b64encode(enc_key).decode(),
        "nonce":   base64.b64encode(nonce).decode(),
        "ct":      base64.b64encode(ct).decode(),
    }}).encode()
'''

    S = "═" * 68
    print(f"\n{S}")
    print("  🔑  PRIVATE KEY — ulož do trezoru")
    print(S)
    print(priv_pem)
    print(S)
    print("  📢  PUBLIC KEY — dej agentovi (nebo jen dej encrypt blok níže)")
    print(S)
    print(pub_pem)
    print(S)
    print("  📦  ENCRYPT FUNKCE — vlož do backup skriptu agenta")
    print(S)
    print(encrypt_py)
    print(S)
    print("  ✅  Roundtrip test: PASSED (RSA-4096 + AES-256-GCM)")
    print(S + "\n")

if __name__ == "__main__":
    main()
