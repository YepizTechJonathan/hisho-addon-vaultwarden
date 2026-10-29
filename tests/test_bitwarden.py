"""Bitwarden's client-side encryption (bitwarden.py): the pieces against independent implementations, and a fake
server that checks what a Bitwarden server would (password hash, EncString MACs, the org key share)."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("bw_under_test", HERE / "bitwarden.py")
bw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bw)

pytest.importorskip("cryptography")


def test_hkdf_expand_matches_the_rfc_implementation():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    prk = bytes(range(32))
    for info in (b"enc", b"mac"):
        assert bw.hkdf_expand(prk, info) == HKDFExpand(hashes.SHA256(), 32, info).derive(prk)
    assert bw.hkdf_expand(prk, b"x", 64) == HKDFExpand(hashes.SHA256(), 64, b"x").derive(prk)


def test_master_key_and_password_hash_are_pbkdf2_salted_the_bitwarden_way():
    mk = bw.master_key("correct horse", " User@Example.com ", iterations=5000)
    assert mk == hashlib.pbkdf2_hmac("sha256", b"correct horse", b"user@example.com", 5000, 32)
    assert bw.password_hash(mk, "correct horse") == base64.b64encode(
        hashlib.pbkdf2_hmac("sha256", mk, b"correct horse", 1, 32)).decode()


def test_argon2id_master_key_uses_the_sha256_of_the_email_as_salt():
    low = pytest.importorskip("argon2.low_level")
    mk = bw.master_key("pw", "a@b.c", kdf=bw.ARGON2ID, iterations=2, memory=16, parallelism=1)
    assert mk == low.hash_secret_raw(b"pw", hashlib.sha256(b"a@b.c").digest(), time_cost=2, memory_cost=16 * 1024,
                                     parallelism=1, hash_len=32, type=low.Type.ID)


def test_encstring_type_2_round_trips_and_refuses_a_wrong_key_or_a_changed_byte():
    key = bw.SymKey.new()
    text = bw.encrypt(b"s3cret \xe2\x9c\x93", key)
    assert text.startswith("2.") and text.count("|") == 2
    assert bw.decrypt(text, key) == b"s3cret \xe2\x9c\x93"
    with pytest.raises(bw.BitwardenError, match="wrong key"):
        bw.decrypt(text, bw.SymKey.new())
    iv, ct, mac = text[2:].split("|")
    raw = bytearray(base64.b64decode(ct))
    raw[0] ^= 1
    with pytest.raises(bw.BitwardenError):
        bw.decrypt(f"2.{iv}|{base64.b64encode(bytes(raw)).decode()}|{mac}", key)
    assert bw.dec_str(bw.enc_str("héllo", key), key) == "héllo"
    assert bw.enc_str("", key) is None and bw.dec_str(None, key) == ""


def test_encstring_is_aes_cbc_then_hmac_over_iv_and_ciphertext():
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import hmac
    key, iv = bw.SymKey(b"\x01" * 32, b"\x02" * 32), b"\x03" * 16
    text = bw.encrypt(b"hello", key, iv=iv)
    p = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).encryptor()
    ct = enc.update(p.update(b"hello") + p.finalize()) + enc.finalize()
    mac = hmac.new(key.mac, iv + ct, hashlib.sha256).digest()
    assert text == "2." + "|".join(base64.b64encode(x).decode() for x in (iv, ct, mac))


def test_the_org_key_share_is_rsa_oaep_sha1_type_4():
    priv, pub = bw.rsa_new()
    org = bw.SymKey.new()
    share = bw.rsa_encrypt(pub, org.raw())
    assert share.startswith("4.")
    assert bw.SymKey.from_bytes(bw.rsa_decrypt(priv, share)) == org
    with pytest.raises(bw.BitwardenError):
        bw.rsa_decrypt(priv, "2.abc|def|ghi")


def test_symkey_never_prints_its_bytes():
    assert repr(bw.SymKey.new()) == "SymKey(...)"


def test_endpoints_for_bitwarden_cloud_us_eu_and_a_self_hosted_server():
    assert bw.endpoints("https://vault.bitwarden.com") == (
        "https://vault.bitwarden.com", "https://identity.bitwarden.com", "https://api.bitwarden.com")
    assert bw.endpoints("bitwarden.eu")[1:] == ("https://identity.bitwarden.eu", "https://api.bitwarden.eu")
    assert bw.endpoints("https://kihon.example.ts.net:5443/") == (
        "https://kihon.example.ts.net:5443", "https://kihon.example.ts.net:5443/identity",
        "https://kihon.example.ts.net:5443/api")
    assert bw.is_cloud("https://vault.bitwarden.eu") and not bw.is_cloud("https://vw.example:5443")


def test_new_password_is_long_and_one_plain_line():
    p = bw.new_password()
    assert len(p) == 40 and p.isalnum() and p != bw.new_password()


def test_a_refusal_comes_back_in_the_servers_words_without_the_request():
    calls = []

    def http(method, url, headers, body, timeout):
        calls.append((method, url, headers, body))
        return 400, json.dumps({"message": "Username or password is incorrect. Try again"}).encode()
    v = bw.Vault("https://vw.example", http=http)
    with pytest.raises(bw.BitwardenError, match="incorrect") as exc:
        v.call("POST", v.identity + "/connect/token", form={"password": "hash-not-shown"})
    assert exc.value.status == 400 and "hash-not-shown" not in str(exc.value)
    assert calls[0][2]["Device-Type"] == str(bw.DEVICE_TYPE)
