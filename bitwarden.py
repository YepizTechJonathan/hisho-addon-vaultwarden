"""Bitwarden's client-side encryption and the few API calls Hisho needs, for Vaultwarden and Bitwarden cloud.

Everything is encrypted on this side; the server only ever sees ciphertext and a password *hash*:

    master key      PBKDF2-SHA256(password, salt=email) or Argon2id(password, salt=SHA256(email))
    password hash   PBKDF2-SHA256(master key, salt=password, 1 round): what the server checks at sign-in
    stretched key   HKDF-Expand(master key, "enc") + HKDF-Expand(master key, "mac"): unlocks the user key
    user key        64 random bytes (32 AES + 32 HMAC); unlocks the account's RSA private key and its items
    EncString 2     "2.<iv>|<ciphertext>|<mac>": AES-256-CBC + HMAC-SHA256 over iv + ciphertext
    EncString 4     "4.<ciphertext>": RSA-2048 OAEP (SHA-1), how an organization's key reaches a member

An organization has its own 64-byte key. Hisho's account makes the organization, so it holds that key (encrypted
to its own RSA key); confirming the owner encrypts the same key to the owner's *public* key, which the server hands
out. Items Hisho saves in the organization are encrypted with that key, so the owner's apps can open them and the
server can't. Only ``cryptography`` (Apache-2.0/BSD) is needed; ``argon2-cffi`` (MIT) only for an Argon2 account.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

PBKDF2, ARGON2ID = 0, 1
PBKDF2_ITERATIONS = 600_000          # Bitwarden's default for new accounts
DEVICE_TYPE = 25                     # LinuxCLI
CLIENT_NAME, CLIENT_VERSION = "cli", "2026.9.0"
#: organization member types and states (Bitwarden's numbers)
OWNER, ADMIN, USER, MANAGER = 0, 1, 2, 3
INVITED, ACCEPTED, CONFIRMED, REVOKED = 0, 1, 2, -1
CLOUD = {"vault.bitwarden.com": ("https://identity.bitwarden.com", "https://api.bitwarden.com"),
         "vault.bitwarden.eu": ("https://identity.bitwarden.eu", "https://api.bitwarden.eu")}


class BitwardenError(RuntimeError):
    """A refusal or failure, in words the page can show. Never carries a password or key."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


def _crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import hashes, padding, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as apadding, rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:   # Core's install has it ([push] extra); a bare venv may not
        raise BitwardenError("Python's cryptography package is missing on the Core machine "
                             "(~/code/hisho/.venv/bin/pip install cryptography)")
    return hashes, padding, serialization, apadding, rsa, Cipher, algorithms, modes


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


# ── keys ─────────────────────────────────────────────────────────────────

class SymKey:
    """A Bitwarden symmetric key: 32 bytes for AES-256, 32 for HMAC-SHA256."""
    __slots__ = ("enc", "mac")

    def __init__(self, enc: bytes, mac: bytes) -> None:
        self.enc, self.mac = enc, mac

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SymKey) and hmac.compare_digest(self.raw(), other.raw())

    def __hash__(self) -> int:
        return hash(self.raw())

    @classmethod
    def new(cls) -> "SymKey":
        return cls.from_bytes(secrets.token_bytes(64))

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SymKey":
        if len(raw) != 64:
            raise BitwardenError(f"a symmetric key is 64 bytes, not {len(raw)}")
        return cls(raw[:32], raw[32:])

    def raw(self) -> bytes:
        return self.enc + self.mac

    def __repr__(self) -> str:   # never print key material
        return "SymKey(...)"


def master_key(password: str, email: str, kdf: int = PBKDF2, iterations: int = PBKDF2_ITERATIONS,
               memory: int | None = None, parallelism: int | None = None) -> bytes:
    """The 32-byte master key. ``memory`` is in MiB (Bitwarden's unit) for Argon2id."""
    salt = email.strip().lower().encode()
    if kdf == PBKDF2:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations), 32)
    if kdf == ARGON2ID:
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            raise BitwardenError("this account uses Argon2id; install argon2-cffi on the Core machine")
        return hash_secret_raw(password.encode(), hashlib.sha256(salt).digest(), time_cost=int(iterations),
                               memory_cost=int(memory or 64) * 1024, parallelism=int(parallelism or 4),
                               hash_len=32, type=Type.ID)
    raise BitwardenError(f"unknown key derivation {kdf}")


def password_hash(mkey: bytes, password: str) -> str:
    """What the server stores and checks: one PBKDF2 round of the master key, salted with the password."""
    return b64(hashlib.pbkdf2_hmac("sha256", mkey, password.encode(), 1, 32))


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def stretch(mkey: bytes) -> SymKey:
    return SymKey(hkdf_expand(mkey, b"enc"), hkdf_expand(mkey, b"mac"))


# ── EncStrings ───────────────────────────────────────────────────────────

def encrypt(data: bytes, key: SymKey, iv: bytes | None = None) -> str:
    """EncString type 2: AES-256-CBC (PKCS7) then HMAC-SHA256 over iv + ciphertext."""
    _h, padding, _s, _a, _r, Cipher, algorithms, modes = _crypto()
    iv = iv or secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(key.mac, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def decrypt(text: str, key: SymKey) -> bytes:
    _h, padding, _s, _a, _r, Cipher, algorithms, modes = _crypto()
    kind, _, body = str(text or "").partition(".")
    if kind != "2":
        raise BitwardenError(f"can't open an EncString of type {kind or '?'} with a symmetric key")
    try:
        iv, ct, mac = (unb64(p) for p in body.split("|"))
    except ValueError:
        raise BitwardenError("damaged EncString")
    if not hmac.compare_digest(mac, hmac.new(key.mac, iv + ct, hashlib.sha256).digest()):
        raise BitwardenError("wrong key (the EncString's MAC doesn't match)")
    dec = Cipher(algorithms.AES(key.enc), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def enc_str(text: str | None, key: SymKey) -> str | None:
    return None if text in (None, "") else encrypt(str(text).encode(), key)


def dec_str(text: str | None, key: SymKey) -> str:
    return "" if not text else decrypt(text, key).decode()


def rsa_new() -> tuple[bytes, str]:
    """A new RSA-2048 key pair: (private key as PKCS#8 DER, public key as base64 SPKI DER)."""
    _h, _p, serialization, _a, rsa, *_ = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, b64(pub)


def rsa_encrypt(public_key_b64: str, data: bytes) -> str:
    """EncString type 4: RSA-OAEP with SHA-1 (what every Bitwarden client uses for key shares)."""
    hashes, _p, serialization, apadding, *_ = _crypto()
    pub = serialization.load_der_public_key(unb64(public_key_b64))
    ct = pub.encrypt(data, apadding.OAEP(mgf=apadding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
    return f"4.{b64(ct)}"


def rsa_decrypt(private_der: bytes, text: str) -> bytes:
    hashes, _p, serialization, apadding, *_ = _crypto()
    kind, _, body = str(text or "").partition(".")
    algo = {"3": hashes.SHA256, "4": hashes.SHA1, "5": hashes.SHA256, "6": hashes.SHA1}.get(kind)
    if algo is None:
        raise BitwardenError(f"can't open an EncString of type {kind or '?'} with an RSA key")
    priv = serialization.load_der_private_key(private_der, password=None)
    ct = unb64(body.split("|")[0])
    return priv.decrypt(ct, apadding.OAEP(mgf=apadding.MGF1(algo()), algorithm=algo(), label=None))


def new_password(length: int = 40) -> str:
    """A master password for Hisho's own account: letters and digits only (one line, no shell trouble)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── the server ───────────────────────────────────────────────────────────

Http = Callable[[str, str, dict[str, str], bytes | None, int], tuple[int, bytes]]


def _http(method: str, url: str, headers: dict[str, str], body: bytes | None, timeout: int) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def endpoints(url: str) -> tuple[str, str, str]:
    """(web vault, identity, api) for an address: Bitwarden cloud's own hosts, or one self-hosted server."""
    base = str(url or "").strip().rstrip("/")
    if not base:
        raise BitwardenError("no address")
    if "://" not in base:
        base = "https://" + base
    host = urllib.parse.urlsplit(base).hostname or ""
    if host in CLOUD:
        return (base, *CLOUD[host])
    if host in ("bitwarden.com", "bitwarden.eu"):
        return (f"https://vault.{host}", *CLOUD[f"vault.{host}"])
    return base, base + "/identity", base + "/api"


def is_cloud(url: str) -> bool:
    try:
        return endpoints(url)[1] in {i for i, _ in CLOUD.values()}
    except BitwardenError:
        return False


def _message(status: int, raw: bytes) -> str:
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        return f"the server answered {status}"
    if isinstance(data, dict):
        for k in ("message", "Message", "error_description", "ErrorModel"):
            v = data.get(k)
            if isinstance(v, dict):
                v = v.get("Message") or v.get("message")
            if v:
                return str(v)[:300]
        model = data.get("errorModel") or data.get("validationErrors") or {}
        if model:
            return json.dumps(model)[:300]
    return f"the server answered {status}"


class Vault:
    """One Bitwarden-compatible server and one signed-in account (or none, for registering)."""

    def __init__(self, url: str, http: Http | None = None, device_id: str | None = None, timeout: int = 30) -> None:
        self.web, self.identity, self.api = endpoints(url)
        self.http = http or _http
        self.device_id = device_id or str(uuid.uuid4())
        self.timeout = timeout
        self.token = ""
        self.email = ""
        self.user_key: SymKey | None = None
        self.private_key: bytes | None = None
        self.public_key = ""
        self.user_id = ""
        self._org_keys: dict[str, SymKey] = {}
        self._sync: dict[str, Any] | None = None

    # plumbing
    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {"Accept": "application/json", "Device-Type": str(DEVICE_TYPE), "Bitwarden-Client-Name": CLIENT_NAME,
             "Bitwarden-Client-Version": CLIENT_VERSION, "User-Agent": "Hisho (vaultwarden add-on)"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return {**h, **(extra or {})}

    def call(self, method: str, url: str, data: Any = None, form: dict[str, str] | None = None,
             headers: dict[str, str] | None = None, ok: tuple[int, ...] = (200, 204)) -> Any:
        body, extra = None, dict(headers or {})
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            extra["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        elif data is not None:
            body = json.dumps(data).encode()
            extra["Content-Type"] = "application/json; charset=utf-8"
        try:
            status, raw = self.http(method, url, self._headers(extra), body, self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BitwardenError(f"can't reach {self.web} ({getattr(exc, 'reason', exc)})")
        if status not in ok:
            raise BitwardenError(_message(status, raw), status)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def alive(self) -> bool:
        try:
            status, _ = self.http("GET", self.web + "/alive", {"Accept": "*/*"}, None, 10)
        except (urllib.error.URLError, TimeoutError, OSError):
            return False
        return status == 200

    # accounts
    def prelogin(self, email: str) -> dict[str, Any]:
        data = self.call("POST", self.identity + "/accounts/prelogin", {"email": email}) or {}
        low = {k.lower(): v for k, v in data.items()}
        return {"kdf": int(low.get("kdf") or 0), "iterations": int(low.get("kdfiterations") or PBKDF2_ITERATIONS),
                "memory": low.get("kdfmemory"), "parallelism": low.get("kdfparallelism")}

    def register(self, email: str, password: str, name: str = "Hisho", hint: str | None = None) -> None:
        """A new account (PBKDF2, 600000 rounds): user key, RSA keys, all made and encrypted here."""
        mkey = master_key(password, email)
        user_key = SymKey.new()
        priv, pub = rsa_new()
        token = self.registration_token(email, name)
        body = {"email": email, "emailVerificationToken": token, "masterPasswordHash": password_hash(mkey, password),
                "masterPasswordHint": hint, "userSymmetricKey": encrypt(user_key.raw(), stretch(mkey)),
                "userAsymmetricKeys": {"publicKey": pub, "encryptedPrivateKey": encrypt(priv, user_key)},
                "kdf": PBKDF2, "kdfIterations": PBKDF2_ITERATIONS, "kdfMemory": None, "kdfParallelism": None}
        self.call("POST", self.identity + "/accounts/register/finish", body)

    def registration_token(self, email: str, name: str = "") -> str:
        """Bitwarden's two-step sign-up: a server without email (Vaultwarden, no SMTP) hands the email-check token
        straight back; one that sends mail answers with nothing and mails a link instead."""
        try:
            status, raw = self.http("POST", self.identity + "/accounts/register/send-verification-email",
                                    {**self._headers(), "Content-Type": "application/json; charset=utf-8"},
                                    json.dumps({"email": email, "name": name,
                                                "receiveMarketingEmails": False}).encode(), self.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BitwardenError(f"can't reach {self.web} ({getattr(exc, 'reason', exc)})")
        if status not in (200, 204):
            raise BitwardenError(_message(status, raw), status)
        token = (raw or b"").decode().strip().strip('"')
        if not token:
            raise BitwardenError("this server emails a sign-up link instead (it sends mail); make the account in "
                                 "its web vault, then give Hisho its email and master password")
        return token

    def _token(self, form: dict[str, str], email: str, password: str, extra: dict[str, str] | None = None) -> None:
        form = {**form, "deviceType": str(DEVICE_TYPE), "deviceIdentifier": self.device_id, "deviceName": "Hisho"}
        data = self.call("POST", self.identity + "/connect/token", form=form, headers=extra)
        low = {k.lower(): v for k, v in (data or {}).items()}
        if not low.get("access_token"):
            raise BitwardenError("sign-in gave no token")
        self.token, self.email = low["access_token"], email
        kdf = {"kdf": int(low.get("kdf") or 0), "iterations": int(low.get("kdfiterations") or PBKDF2_ITERATIONS),
               "memory": low.get("kdfmemory"), "parallelism": low.get("kdfparallelism")}
        if low.get("key") is None:      # client credentials on some servers: the KDF comes from prelogin
            kdf = self.prelogin(email)
        self._unlock(low.get("key"), low.get("privatekey"), password, email, kdf)

    def _unlock(self, key: str | None, private: str | None, password: str, email: str, kdf: dict[str, Any]) -> None:
        if not key:
            profile = self.sync(force=True).get("profile") or {}
            key, private = profile.get("key"), profile.get("privateKey")
        mkey = master_key(password, email, kdf["kdf"], kdf["iterations"], kdf.get("memory"), kdf.get("parallelism"))
        try:
            self.user_key = SymKey.from_bytes(decrypt(key or "", stretch(mkey)))
        except BitwardenError as exc:
            raise BitwardenError(f"the master password doesn't open this account's key ({exc})")
        if private:
            self.private_key = decrypt(private, self.user_key)

    def login(self, email: str, password: str) -> None:
        """Sign in with the master password (Vaultwarden; Bitwarden cloud may ask for a captcha or a new-device
        code this way: use ``login_api_key`` there)."""
        pre = self.prelogin(email)
        mkey = master_key(password, email, pre["kdf"], pre["iterations"], pre.get("memory"), pre.get("parallelism"))
        auth = base64.urlsafe_b64encode(email.encode()).decode().rstrip("=")
        self._token({"grant_type": "password", "username": email, "password": password_hash(mkey, password),
                     "scope": "api offline_access", "client_id": CLIENT_NAME}, email, password, {"Auth-Email": auth})

    def login_api_key(self, client_id: str, client_secret: str, email: str, password: str) -> None:
        """Sign in with the account's personal API key (Account settings > Security > Keys); the master password
        still unlocks the keys. No captcha, no new-device email: how Hisho signs in to Bitwarden cloud."""
        self._token({"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret,
                     "scope": "api"}, email, password)

    def sync(self, force: bool = False) -> dict[str, Any]:
        if self._sync is None or force:
            self._sync = _lower(self.call("GET", self.api + "/sync?excludeDomains=true") or {})
            prof = self._sync.get("profile") or {}
            self.user_id = str(prof.get("id") or self.user_id)
        return self._sync

    # organizations
    def org_key(self, org_id: str) -> SymKey:
        if org_id in self._org_keys:
            return self._org_keys[org_id]
        for o in (self.sync().get("profile") or {}).get("organizations") or []:
            if str(o.get("id")) == org_id and o.get("key"):
                if self.private_key is None:
                    raise BitwardenError("this account has no private key to open the organization's key")
                self._org_keys[org_id] = SymKey.from_bytes(rsa_decrypt(self.private_key, o["key"]))
                return self._org_keys[org_id]
        raise BitwardenError("this account is not a confirmed member of that organization")

    def organizations(self) -> list[dict[str, Any]]:
        return list((self.sync().get("profile") or {}).get("organizations") or [])

    def my_public_key(self) -> str:
        if self.private_key is None:
            raise BitwardenError("this account has no RSA key")
        _h, _p, serialization, *_ = _crypto()
        priv = serialization.load_der_private_key(self.private_key, password=None)
        return b64(priv.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))

    def create_org(self, name: str, collection: str, billing_email: str) -> tuple[str, SymKey]:
        """A free organization with one collection; the organization key stays on this side."""
        org_key = SymKey.new()
        priv, pub = rsa_new()
        body = {"name": name, "billingEmail": billing_email, "planType": 0,
                "key": rsa_encrypt(self.my_public_key(), org_key.raw()),
                "keys": {"publicKey": pub, "encryptedPrivateKey": encrypt(priv, org_key)},
                "collectionName": enc_str(collection, org_key)}
        data = _lower(self.call("POST", self.api + "/organizations", body) or {})
        org_id = str(data.get("id") or "")
        if not org_id:
            raise BitwardenError("the server made no organization")
        self._org_keys[org_id] = org_key
        self._sync = None
        return org_id, org_key

    def collections(self, org_id: str) -> list[dict[str, Any]]:
        key = self.org_key(org_id)
        data = _lower(self.call("GET", f"{self.api}/organizations/{org_id}/collections") or {})
        out = []
        for c in data.get("data") or []:
            try:
                out.append({"id": str(c.get("id")), "name": dec_str(c.get("name"), key)})
            except BitwardenError:
                out.append({"id": str(c.get("id")), "name": "?"})
        return out

    def create_collection(self, org_id: str, name: str) -> str:
        data = _lower(self.call("POST", f"{self.api}/organizations/{org_id}/collections",
                                {"name": enc_str(name, self.org_key(org_id)), "groups": [], "users": []}) or {})
        return str(data.get("id") or "")

    def members(self, org_id: str) -> list[dict[str, Any]]:
        data = _lower(self.call("GET", f"{self.api}/organizations/{org_id}/users") or {})
        return [{"id": str(m.get("id")), "user_id": str(m.get("userid") or ""), "email": str(m.get("email") or ""),
                 "status": int(m.get("status") if m.get("status") is not None else INVITED),
                 "type": int(m.get("type") or 0)} for m in data.get("data") or []]

    def invite(self, org_id: str, email: str, collection_id: str, kind: int = ADMIN) -> None:
        cols = [{"id": collection_id, "readOnly": False, "hidePasswords": False, "manage": True}] if collection_id else []
        self.call("POST", f"{self.api}/organizations/{org_id}/users/invite",
                  {"emails": [email], "type": kind, "collections": cols, "groups": [], "accessAll": False,
                   "permissions": {}})

    def public_key_of(self, user_id: str) -> str:
        data = _lower(self.call("GET", f"{self.api}/users/{user_id}/public-key") or {})
        if not data.get("publickey"):
            raise BitwardenError("that account has no public key yet (it was never signed in to)")
        return str(data["publickey"])

    def confirm(self, org_id: str, member: dict[str, Any]) -> None:
        """Bitwarden's confirm step: the organization key, encrypted to the member's own public key."""
        if not member.get("user_id"):
            raise BitwardenError(f"{member.get('email')} has no account yet")
        key = rsa_encrypt(self.public_key_of(member["user_id"]), self.org_key(org_id).raw())
        self.call("POST", f"{self.api}/organizations/{org_id}/users/{member['id']}/confirm", {"key": key})

    # items
    def org_items(self, org_id: str) -> list[dict[str, Any]]:
        """The organization's logins, opened: {id, name, username, password, uris, fields, notes, collections}."""
        key = self.org_key(org_id)
        out = []
        for c in self.sync(force=True).get("ciphers") or []:
            if str(c.get("organizationid") or "") != org_id or int(c.get("type") or 0) != 1:
                continue
            item_key = key
            if c.get("key"):   # an item with its own key (newer clients)
                item_key = SymKey.from_bytes(decrypt(c["key"], key))
            login = c.get("login") or {}
            try:
                out.append({"id": str(c.get("id")), "name": dec_str(c.get("name"), item_key),
                            "notes": dec_str(c.get("notes"), item_key),
                            "username": dec_str(login.get("username"), item_key),
                            "password": dec_str(login.get("password"), item_key),
                            "uris": [dec_str(u.get("uri"), item_key) for u in login.get("uris") or []],
                            "fields": {dec_str(f.get("name"), item_key): dec_str(f.get("value"), item_key)
                                       for f in c.get("fields") or []},
                            "collections": [str(x) for x in c.get("collectionids") or []],
                            "revision": c.get("revisiondate")})
            except BitwardenError:
                continue   # not openable with this key: not one of ours
        return out

    def put_login(self, org_id: str, collection_id: str, item: dict[str, Any], item_id: str | None = None,
                  revision: str | None = None) -> str:
        """Make (or, with ``item_id``, change) a login item in the organization's collection; returns its id."""
        key = self.org_key(org_id)
        uris = [{"uri": enc_str(u, key), "match": None} for u in item.get("uris") or [] if u]
        if not self.user_id:
            self.sync()
        # encryptedFor: which account encrypted it (current servers refuse an item without it)
        cipher = {"type": 1, "organizationId": org_id, "encryptedFor": self.user_id, "folderId": None,
                  "favorite": False, "reprompt": 0,
                  "name": enc_str(item["name"], key), "notes": enc_str(item.get("notes"), key),
                  "login": {"username": enc_str(item.get("username"), key),
                            "password": enc_str(item.get("password"), key), "uris": uris or None, "totp": None},
                  "fields": [{"name": enc_str(k, key), "value": enc_str(v, key), "type": 0}
                             for k, v in (item.get("fields") or {}).items()],
                  "collectionIds": [collection_id]}
        if item_id:
            if revision:
                cipher["lastKnownRevisionDate"] = revision
            data = self.call("PUT", f"{self.api}/ciphers/{item_id}", cipher)
        else:
            data = self.call("POST", f"{self.api}/ciphers/create", {"cipher": cipher, "collectionIds": [collection_id]})
        return str((_lower(data or {})).get("id") or item_id or "")


    def trash(self, item_id: str) -> None:
        """Move an item to the vault's trash (the owner can restore it there; never a permanent delete)."""
        self.call("PUT", f"{self.api}/ciphers/{item_id}/delete")


def _lower(data: Any) -> Any:
    """Bitwarden answers in camelCase, older servers in PascalCase: keys lower-cased, all the way down."""
    if isinstance(data, dict):
        return {str(k).lower(): _lower(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_lower(v) for v in data]
    return data


def device_id_for(seed: str) -> str:
    """A stable device id per server and account, so Bitwarden sees one known device (no new-device emails)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "hisho-vaultwarden:" + seed))

