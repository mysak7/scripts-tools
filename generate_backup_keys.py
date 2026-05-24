#!/usr/bin/env python3
"""
generate_backup_keys.py
-----------------------
Vygeneruje RSA-4096 keypair pro šifrování záloh.

Výstup:
  - private_key.pem      → ulož do trezoru (Bitwarden, offline USB…)
  - public_key.pem       → dej backup agentovi (Hermes apod.)
  - encrypt_snippet.py   → vlož do backup skriptu agenta
  - decrypt_backup.py    → tvůj lokální dešifrovač

Použití:
  python3 generate_backup_keys.py
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64, json, sys
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "backup_keys"

# ── Šablony ──────────────────────────────────────────────────────────────────

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

DECRYPT_HELPER_TEMPLATE = '''\
#!/usr/bin/env python3
"""
decrypt_backup.py — lokální dešifrovač zálohy
Použití: python3 decrypt_backup.py <záloha.enc.json> <výstup>
Závislost: pip install cryptography
"""
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys, base64, json
from pathlib import Path

# Cesta k private key (uprav pokud potřeba)
PRIVATE_KEY_PATH = Path(__file__).parent / "private_key.pem"


def decrypt_backup(enc_path: str, out_path: str) -> None:
    priv_pem = Path(PRIVATE_KEY_PATH).read_bytes()
    priv = serialization.load_pem_private_key(priv_pem, password=None)

    p = json.loads(Path(enc_path).read_bytes())
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
    print(f"✅  Dešifrováno → {{out_path}}  ({{len(data):,}} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Použití: python3 decrypt_backup.py <záloha.enc.json> <výstup>")
        sys.exit(1)
    decrypt_backup(sys.argv[1], sys.argv[2])
'''


# ── Hlavní logika ─────────────────────────────────────────────────────────────

def generate_keypair():
    print("🔑  Generuji RSA-4096 keypair…")
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
    """Ověří, že encrypt→decrypt funguje správně."""
    test = b"backup-roundtrip-test"
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


def save_files(priv_pem, pub_pem):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    (OUTPUT_DIR / "private_key.pem").write_text(priv_pem)
    os.chmod(OUTPUT_DIR / "private_key.pem", 0o600)

    (OUTPUT_DIR / "public_key.pem").write_text(pub_pem)

    (OUTPUT_DIR / "encrypt_snippet.py").write_text(
        ENCRYPT_SNIPPET_TEMPLATE.format(pub_pem=pub_pem.strip())
    )

    (OUTPUT_DIR / "decrypt_backup.py").write_text(DECRYPT_HELPER_TEMPLATE)
    os.chmod(OUTPUT_DIR / "decrypt_backup.py", 0o755)


def main():
    private_key, public_key, priv_pem, pub_pem = generate_keypair()

    print("🔄  Ověřuji roundtrip (encrypt → decrypt)…")
    verify_roundtrip(private_key, public_key)
    print("✅  Roundtrip OK (RSA-4096 + AES-256-GCM)\n")

    save_files(priv_pem, pub_pem)

    SEP = "═" * 64
    print(SEP)
    print(f"  Soubory uloženy do: {OUTPUT_DIR}/")
    print(SEP)
    print(f"  🔑  private_key.pem     → ULOŽ DO TREZORU, smaž odtud!")
    print(f"  📢  public_key.pem      → dej backup agentovi")
    print(f"  📦  encrypt_snippet.py  → vlož do backup_hermes.py")
    print(f"  🔓  decrypt_backup.py   → tvůj lokální dešifrovač")
    print(SEP)
    print()
    print("⚠️   Po uložení private_key.pem do trezoru spusť:")
    print(f"      rm {OUTPUT_DIR}/private_key.pem")
    print()


if __name__ == "__main__":
    main()
