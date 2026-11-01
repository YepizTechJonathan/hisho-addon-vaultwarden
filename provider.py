"""Bitwarden / Vaultwarden for Hisho (see addon.yaml): passwords kept safe, in the owner's own password vault.

Hisho has its own account on the vault (a long generated master password, kept as a secret) and owns an
organization "Hisho" with one collection "Hisho logins". The owner's own account is invited to it and, once it has
joined, confirmed (Bitwarden's confirm step: the organization key encrypted to the owner's public key, done here).
From then on every login Hisho makes or is given (``save_login``) is written into that collection, encrypted on
this side with the organization's key: the owner's Bitwarden apps open it, the server never sees it in the clear.

Setup runs by itself (``setup``: from the card's checks and from the page's buttons):

    1. Hisho's account     Vaultwarden: made here (sign-ups are open right after install). Bitwarden cloud: the owner
                           makes a second free account and gives Hisho its email, master password and API key.
    2. Organization        "Hisho" with the collection "Hisho logins" (a free organization on Bitwarden cloud).
    3. Your account        the owner types the email of their account; Hisho invites it. Vaultwarden without mail:
                           an existing account joins at once; a new one joins when it is made with that email (even
                           with sign-ups closed). Bitwarden cloud: the owner accepts the invite in the email.
    4. Confirm             Hisho confirms the owner as soon as they have joined.
    5. Sign-ups closed     Vaultwarden that Hisho installed: SIGNUPS_ALLOWED=false and a restart, once the owner is
                           invited (their invite still lets them make their account).

Contract for other parts of Hisho (manifest ``login_store: true``)::

    save_login(login, ctx) -> {"ok": bool, "message": "...", "id": "<item id>"}
        login = {name, service, machine, url, username, password, note}; name and password are needed.
        An item of that name that Hisho made (its "Made by: Hisho" field) is changed in place; anything else, the
        owner's own items included, is never touched. The password never reaches a message, a log or the journal.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import secrets as _secrets
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_spec = importlib.util.spec_from_file_location("hisho_addon_vaultwarden_bitwarden", Path(__file__).with_name("bitwarden.py"))
bw = importlib.util.module_from_spec(_spec)
assert _spec.loader
_spec.loader.exec_module(bw)

ORG_NAME = "Hisho"
COLLECTION = "Hisho logins"
MADE_BY = ("Made by", "Hisho")              # the field that marks an item Hisho made (and may change)
SESSION_SECONDS = 20 * 60                   # a sign-in is reused this long (Vaultwarden's token lasts 2 h)
SETUP_EVERY = 60                            # an unfinished setup is retried at most this often by the checks
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
APPS = "https://bitwarden.com/download/"
_sessions: dict[str, tuple[float, Any]] = {}


# ── where things are ─────────────────────────────────────────────────────

def state_path(entry: str) -> Path:
    base = Path(os.environ.get("HISHO_STATE_DIR") or "~/.local/state/hisho").expanduser()
    return base / "addons" / "vaultwarden" / f"{re.sub(r'[^A-Za-z0-9._-]', '_', entry)}.json"


def load_state(entry: str) -> dict[str, Any]:
    try:
        return json.loads(state_path(entry).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(entry: str, state: dict[str, Any]) -> None:
    p = state_path(entry)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def managed(entry: dict[str, Any]) -> bool:
    """A Vaultwarden Hisho installed on this machine (its data folder named in the entry)."""
    return bool(entry.get("data_dir")) and not bw.is_cloud(str(entry.get("url") or ""))


def env_file(entry: dict[str, Any]) -> Path:
    return Path(str(entry["data_dir"])).expanduser() / "config" / "vaultwarden.env"


def hisho_email(entry: dict[str, Any], ctx: Any) -> str:
    if entry.get("hisho_email"):
        return str(entry["hisho_email"]).strip().lower()
    machine = getattr(getattr(ctx, "fleet", None), "core_host", "") or socket.gethostname().split(".")[0]
    return f"hisho@{re.sub(r'[^a-z0-9-]', '-', str(machine).lower())}.local"


def _addons() -> Any:
    from hisho import addons
    return addons


def _entries(ctx: Any) -> dict[str, dict[str, Any]]:
    return _addons().entries(ctx.addon)


def _set_entry(ctx: Any, name: str, values: dict[str, Any]) -> None:
    """Merge into the entry; a password field's value becomes a secret on Core (the entry keeps its name)."""
    _addons().set_entry(ctx.addon, name, values, merge=True)


def _journal(event: str, meta: dict[str, Any]) -> None:
    try:
        from hisho.jobs import append_event
        append_event(Path(os.environ.get("HISHO_ROOT") or "~/Hisho").expanduser(), event, meta)
    except Exception:  # noqa: BLE001 -- the journal never blocks a save
        pass


def _docker_env() -> dict[str, str]:
    """Rootless Docker's socket when Core (a system unit) has no DOCKER_HOST of its own."""
    if os.environ.get("DOCKER_HOST"):
        return {}
    sock = Path(f"/run/user/{os.getuid()}/docker.sock")
    return {"DOCKER_HOST": f"unix://{sock}"} if sock.exists() else {}


def _run(ctx: Any, cmd: list[str], timeout: int = 60) -> "subprocess.CompletedProcess[str]":
    if ctx is not None and hasattr(ctx, "run"):
        return ctx.run(cmd, timeout=timeout, env=_docker_env())
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **_docker_env()})


def _now() -> float:
    return time.time()


def ago(seconds: float) -> str:
    s = max(0, int(seconds))
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if s >= n:
            return f"{s // n} {unit}"
    return f"{s} s"


def _scrub(text: str, *values: str) -> str:
    for v in values:
        if v:
            text = text.replace(v, "***")
    return text


# ── signing in ───────────────────────────────────────────────────────────

def session(entry: dict[str, Any], ctx: Any, *, fresh: bool = False) -> Any:
    """Hisho's own account, signed in and unlocked (reused for a while)."""
    if not entry.get("hisho_password"):
        raise bw.BitwardenError("Hisho has no account on this vault yet")
    email = hisho_email(entry, ctx)
    key = f"{entry['url']}|{email}"
    hit = _sessions.get(key)
    if hit and not fresh and _now() - hit[0] < SESSION_SECONDS:
        return hit[1]
    v = bw.Vault(str(entry["url"]), device_id=bw.device_id_for(key))
    password = ctx.secret(entry["hisho_password"])
    if entry.get("hisho_client_id") and entry.get("hisho_client_secret"):
        v.login_api_key(str(entry["hisho_client_id"]), ctx.secret(entry["hisho_client_secret"]), email, password)
    else:
        v.login(email, password)
    _sessions[key] = (_now(), v)
    return v


def _with_session(entry: dict[str, Any], ctx: Any, fn: Any) -> Any:
    """Run ``fn(vault)``; a sign-in that ran out (401) is made again once."""
    try:
        return fn(session(entry, ctx))
    except bw.BitwardenError as exc:
        if exc.status != 401:
            raise
        return fn(session(entry, ctx, fresh=True))


# ── setup ────────────────────────────────────────────────────────────────

def make_hisho_account(name: str, entry: dict[str, Any], ctx: Any, st: dict[str, Any]) -> dict[str, Any]:
    """Vaultwarden: Hisho registers its own account. The password is saved (as a secret) before the account is
    made, so a failure in between never leaves an account nobody can open; the next try uses the same one."""
    if bw.is_cloud(str(entry["url"])):
        raise bw.BitwardenError("on Bitwarden cloud, make Hisho's account yourself (a second free account) and "
                                "give its email, master password and API key on this entry")
    email = hisho_email(entry, ctx)
    if entry.get("hisho_password"):
        password = ctx.secret(entry["hisho_password"])
    else:
        password = bw.new_password()
        _set_entry(ctx, name, {"hisho_email": email, "hisho_password": password})
    entry = _entries(ctx).get(name) or {**entry, "hisho_email": email}
    try:
        bw.Vault(str(entry["url"])).register(email, password, name="Hisho")
    except bw.BitwardenError as exc:
        try:   # made on an earlier try that didn't get to say so: signing in tells
            bw.Vault(str(entry["url"])).login(email, password)
        except bw.BitwardenError:
            raise bw.BitwardenError(f"Hisho couldn't make its account {email}: {exc}"
                                    + (" (sign-ups are closed: open them on the admin page, or give Hisho an "
                                       "invite for that email)" if "not allowed" in str(exc).lower() else ""))
    st["hisho_registered"] = _now()
    save_state(name, st)
    _journal("vaultwarden-account", {"entry": name, "email": email, "url": entry["url"]})
    return entry


def make_org(name: str, entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    def go(v: Any) -> dict[str, str]:
        for o in v.organizations():          # one made before (an entry that lost its ids): used again
            if o.get("name") == ORG_NAME and int(o.get("type") or 0) == bw.OWNER:
                org_id = str(o["id"])
                cols = [c for c in v.collections(org_id) if c["name"] == COLLECTION]
                col = cols[0]["id"] if cols else v.create_collection(org_id, COLLECTION)
                return {"org_id": org_id, "collection_id": col}
        org_id, _key = v.create_org(ORG_NAME, COLLECTION, hisho_email(entry, ctx))
        cols = [c for c in v.collections(org_id) if c["name"] == COLLECTION]
        return {"org_id": org_id, "collection_id": cols[0]["id"] if cols else v.create_collection(org_id, COLLECTION)}
    ids = _with_session(entry, ctx, go)
    _set_entry(ctx, name, ids)
    _journal("vaultwarden-org", {"entry": name, "organization": ORG_NAME, "collection": COLLECTION})
    return {**entry, **ids}


def owner_member(entry: dict[str, Any], ctx: Any) -> dict[str, Any] | None:
    email = str(entry.get("owner_email") or "").strip().lower()
    if not email:
        return None
    members = _with_session(entry, ctx, lambda v: v.members(str(entry["org_id"])))
    return next((m for m in members if m["email"].lower() == email), None)


def signups_open(entry: dict[str, Any]) -> bool | None:
    """Ask the server for a sign-up token for a made-up address (Vaultwarden hands one back while sign-ups are
    open and makes nothing). Only for a Vaultwarden Hisho installed: Bitwarden cloud would send a real email."""
    if not managed(entry):
        return None
    try:
        bw.Vault(str(entry["url"])).registration_token(f"signup-check-{_secrets.token_hex(4)}@invalid.local")
        return True
    except bw.BitwardenError as exc:
        return False if exc.status in (400, 403, 422) or "not allowed" in str(exc).lower() else None


def close_signups(entry: dict[str, Any], ctx: Any, wait: float = 90) -> str:
    """SIGNUPS_ALLOWED=false in Vaultwarden's settings file, then a restart (it reads the file at start)."""
    if not managed(entry):
        return "not a Vaultwarden Hisho installed: sign-ups are its own setting"
    path = env_file(entry)
    text = path.read_text(encoding="utf-8")
    new = re.sub(r"(?m)^SIGNUPS_ALLOWED=.*$", "SIGNUPS_ALLOWED=false", text)
    if "SIGNUPS_ALLOWED=" not in new:
        new = new.rstrip("\n") + "\nSIGNUPS_ALLOWED=false\n"
    if new != text:
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new)
        tmp.replace(path)
    container = str(entry.get("container") or "vaultwarden")
    res = _run(ctx, ["docker", "restart", container], timeout=120)
    if res.returncode:
        raise bw.BitwardenError(f"docker restart {container} failed: {(res.stderr or res.stdout).strip()[-200:]}")
    deadline = _now() + wait
    v = bw.Vault(str(entry["url"]))
    while not v.alive():
        if _now() > deadline:
            raise bw.BitwardenError(f"{container} did not come back after the restart")
        time.sleep(2)
    _journal("vaultwarden-signups-closed", {"url": entry["url"], "container": container})
    return "sign-ups closed (only invited accounts can be made now)"


def setup(name: str, entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Take setup as far as it goes now. Returns {"stage", "message", "done": [...]} (stage ``done`` = finished)."""
    st = load_state(name)
    done: list[str] = []
    out: dict[str, Any] = {"done": done}
    try:
        cloud = bw.is_cloud(str(entry.get("url") or ""))
        if cloud and not entry.get("hisho_password"):
            return _stage(name, st, out, "need-hisho", "Hisho needs its own Bitwarden account: make a second free "
                          "account for it, then give its email, master password and API key on this entry.")
        if not cloud and not entry.get("org_id") and not st.get("hisho_registered"):
            entry = make_hisho_account(name, entry, ctx, st)
            done.append(f"made Hisho's own account ({hisho_email(entry, ctx)})")
        if not entry.get("org_id") or not entry.get("collection_id"):
            entry = make_org(name, entry, ctx)
            done.append(f"made the organization {ORG_NAME} with the collection {COLLECTION}")
        if not entry.get("owner_email"):
            return _stage(name, st, out, "need-email", "Type your account's email (Invite me) so Hisho can invite it.")
        member = owner_member(entry, ctx)
        org = str(entry["org_id"])
        if member is None:
            _with_session(entry, ctx, lambda v: v.invite(org, str(entry["owner_email"]), str(entry["collection_id"])))
            done.append(f"invited {entry['owner_email']}")
            _journal("vaultwarden-invite", {"entry": name, "email": entry["owner_email"]})
            member = owner_member(entry, ctx)
        if managed(entry) and member is not None and not st.get("signups_closed"):
            if signups_open(entry) is not False:
                done.append(close_signups(entry, ctx))
            st["signups_closed"] = _now()
        if member is not None and member["status"] == bw.ACCEPTED:
            _with_session(entry, ctx, lambda v: v.confirm(org, member))
            done.append(f"confirmed {entry['owner_email']}: the {COLLECTION} collection is in your vault now")
            _journal("vaultwarden-confirm", {"entry": name, "email": entry["owner_email"]})
            member = owner_member(entry, ctx)
        status = member["status"] if member else None
        if status == bw.CONFIRMED:
            return _stage(name, st, out, "done", f"Done: {entry['owner_email']} sees the {COLLECTION} collection.")
        if status == bw.REVOKED:
            return _stage(name, st, out, "revoked", f"{entry['owner_email']} was removed from the organization "
                          "in the vault; add them back there (Members), then press Check now.")
        if bw.is_cloud(str(entry["url"])):
            return _stage(name, st, out, "waiting", f"Accept the invite: Bitwarden emailed {entry['owner_email']} "
                          "a link (Join organization). Hisho confirms you within a minute after.")
        return _stage(name, st, out, "waiting", f"Make your account: open {bw.endpoints(entry['url'])[0]} and choose "
                      f"Create account with {entry['owner_email']}. Hisho confirms you within a minute after.")
    except bw.BitwardenError as exc:
        out["error"] = str(exc)
        return _stage(name, st, out, st.get("stage") or "error", str(exc), error=True)


def _stage(name: str, st: dict[str, Any], out: dict[str, Any], stage: str, message: str,
           error: bool = False) -> dict[str, Any]:
    st.update(stage=stage, message=message, checked=_now())
    if error:
        st["setup_error"] = message
    else:
        st.pop("setup_error", None)
    save_state(name, st)
    return {**out, "stage": stage, "message": message}


# ── saving logins ────────────────────────────────────────────────────────

def ready(entry: dict[str, Any]) -> bool:
    return bool(entry.get("hisho_password") and entry.get("org_id") and entry.get("collection_id"))


def _pick(entries: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    ok = [(n, e) for n, e in entries.items() if ready(e)]
    ok.sort(key=lambda ne: ne[0] != "main")
    return ok[0] if ok else None


KEY_FIELD = "Hisho key"   # the login's stable id from Core (login["key"])


def save_login(login: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Write one login into the Hisho logins collection (see the module docstring for the contract)."""
    login = dict(login or {})
    key = str(login.get("key") or "").strip()            # Core's stable id for this login: match by it
    which = str(login.get("name") or "").strip()
    password = str(login.get("password") or "")
    title = str(login.get("title") or "").strip()
    if title:   # one item per service login, e.g. "Semaphore (kihon)", "Infisical encryption key (souko)"
        extra = "" if which in ("", "login") else " " + which.replace("_", " ")
        name = f"{title}{extra}" + (f" ({login['machine']})" if login.get("machine") else "")
    else:
        name = which
    if not name or not password:
        return {"ok": False, "message": "a login needs a name and a password"}
    picked = _pick(_entries(ctx))
    if picked is None:
        return {"ok": False, "message": "Your password vault isn't set up yet (Add-ons > Bitwarden / Vaultwarden): "
                                        "nothing was saved"}
    ename, entry = picked
    fields = {MADE_BY[0]: MADE_BY[1]}
    if key:
        fields[KEY_FIELD] = key
    for k, label in (("service", "Service"), ("machine", "Machine")):
        if login.get(k):
            fields[label] = str(login[k])
    item = {"name": name, "username": str(login.get("username") or ""), "password": password,
            "uris": [str(login["url"])] if login.get("url") else [], "notes": str(login.get("note") or ""),
            "fields": fields, "totp": str(login.get("totp") or "")}   # the vault fills two-step codes from it
    org, col = str(entry["org_id"]), str(entry["collection_id"])

    def go(v: Any) -> tuple[str, bool]:
        ours = [i for i in v.org_items(org) if i["fields"].get(MADE_BY[0]) == MADE_BY[1]]
        mine = ([i for i in ours if i["fields"].get(KEY_FIELD) == key] if key else []) \
            or [i for i in ours if i["name"] == name and not (key and i["fields"].get(KEY_FIELD))]
        if mine:
            return v.put_login(org, col, item, item_id=mine[0]["id"], revision=mine[0].get("revision")), True
        return v.put_login(org, col, item), False
    st = load_state(ename)
    try:
        item_id, updated = _with_session(entry, ctx, go)
    except Exception as exc:  # noqa: BLE001 -- said on the card; the caller decides what to do
        msg = _scrub(f"{type(exc).__name__}: {exc}" if not isinstance(exc, bw.BitwardenError) else str(exc), password)
        st["last_error"] = {"at": _now(), "name": name, "error": msg[:300]}
        save_state(ename, st)
        return {"ok": False, "message": f"Hisho couldn't save {name} in your vault: {msg[:300]}"}
    saved = dict(st.get("saved") or {})
    saved[name] = {"id": item_id, "at": _now(), "service": login.get("service") or "", "machine": login.get("machine") or ""}
    st.update(saved=saved, last_save=_now())
    st.pop("last_error", None)
    save_state(ename, st)
    _journal("vaultwarden-login-saved", {"entry": ename, "name": name, "service": login.get("service") or "",
                                         "machine": login.get("machine") or "", "updated": updated})
    return {"ok": True, "id": item_id,
            "message": f"{'Updated' if updated else 'Saved'} {name} in your vault (collection {COLLECTION})"}


def forget_login(login: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Hisho forgot this login (Remove an add-on, SIB-043): its item goes to the vault's trash, found by its Hisho key
    (only items Hisho made). Restorable from the trash; nothing found is fine."""
    key = str((login or {}).get("key") or "").strip()
    if not key:
        return {"ok": False, "message": "a login to forget needs its key"}
    picked = _pick(_entries(ctx))
    if picked is None:
        return {"ok": False, "message": "Your password vault isn't set up here: delete the item there yourself"}
    ename, entry = picked
    org = str(entry["org_id"])

    def go(v: Any) -> list[str]:
        mine = [i for i in v.org_items(org) if i["fields"].get(MADE_BY[0]) == MADE_BY[1]
                and i["fields"].get(KEY_FIELD) == key]
        for i in mine:
            v.trash(i["id"])
        return [i["name"] for i in mine]
    try:
        gone = _with_session(entry, ctx, go)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": f"Hisho couldn't take it out of your vault: {type(exc).__name__}: {str(exc)[:200]}"}
    _journal("vaultwarden-login-trashed", {"entry": ename, "key": key, "items": len(gone)})
    return {"ok": True, "message": f"moved {', '.join(gone)} to your vault's trash" if gone else "it wasn't in your vault"}


# ── what the page shows ──────────────────────────────────────────────────

def _image(entry: dict[str, Any], ctx: Any) -> str:
    if not managed(entry):
        return ""
    res = _run(ctx, ["docker", "inspect", "-f", "{{.Config.Image}}", str(entry.get("container") or "vaultwarden")], 20)
    return res.stdout.strip() if res.returncode == 0 else ""


def pinned_image() -> str:
    """The image Hisho's install pins (deploy/vaultwarden/versions.env in Hisho's code)."""
    try:
        import hisho
        path = Path(hisho.__file__).resolve().parents[2] / "deploy" / "vaultwarden" / "versions.env"
        m = re.search(r"(?m)^VAULTWARDEN_IMAGE=(\S+)", path.read_text(encoding="utf-8"))
        return m.group(1) if m else ""
    except (ImportError, OSError):
        return ""


def installer() -> Path:
    import hisho
    return Path(hisho.__file__).resolve().parents[2] / "deploy" / "vaultwarden" / "install.sh"


def _tag(image: str) -> str:
    return image.split("@")[0].rsplit(":", 1)[-1] if image else ""


def check(name: str, entry: dict[str, Any], ctx: Any, *, run_setup: bool = True) -> dict[str, Any]:
    st = load_state(name)
    up = bw.Vault(str(entry["url"])).alive() if not bw.is_cloud(str(entry["url"])) else True
    stage = st.get("stage")
    if up and run_setup and stage != "done" and _now() - float(st.get("checked") or 0) >= SETUP_EVERY:
        res = setup(name, (_entries(ctx).get(name) or entry), ctx)
        st, stage = load_state(name), res["stage"]
    saved = st.get("saved") or {}
    return {"name": name, "up": up, "stage": stage or "new", "message": st.get("message") or "",
            "error": st.get("setup_error"), "saved": saved, "last_save": st.get("last_save"),
            "last_error": st.get("last_error"), "signups_closed": st.get("signups_closed"),
            "waiting": len(saved) if stage != "done" else 0}


def _headline(c: dict[str, Any]) -> str:
    if not c["up"]:
        return "Not answering"
    n = len(c["saved"])
    parts = [f"{n} login{'s' if n != 1 else ''} saved"]
    if c["waiting"]:
        parts.append(f"{c['waiting']} waiting for you to join")
    if c["last_save"]:
        parts.append(f"last save {ago(_now() - c['last_save'])} ago")
    if c["stage"] != "done":
        parts.append("setup not finished")
    return " · ".join(parts)


def summary(entries: dict[str, dict[str, Any]], ctx: Any) -> dict[str, Any]:
    if not entries:
        return {"state": "unknown", "headline": "No password vault yet: Install Vaultwarden, or add your Bitwarden "
                                                "cloud", "problems": []}
    checks = [check(n, e, ctx) for n, e in entries.items()]
    problems = []
    for c in checks:
        if not c["up"]:
            problems.append({"title": "Your password vault isn't answering", "severity": "warn", "entry": c["name"],
                             "detail": "Hisho can't save logins there until it is back. Restart Vaultwarden "
                                       "(docker restart vaultwarden on the Core machine)."})
        elif c["stage"] != "done":
            problems.append({"title": "Finish setting up your password vault", "severity": "info", "quiet": True,
                             "entry": c["name"], "detail": c["error"] or c["message"]})
        if c["last_error"]:
            problems.append({"title": f"Hisho couldn't save {c['last_error'].get('name')} in your vault",
                             "severity": "warn", "entry": c["name"], "detail": c["last_error"].get("error")})
    state = "down" if any(not c["up"] for c in checks) else \
        "warn" if any(p["severity"] == "warn" for p in problems) else "ok"
    heads = [_headline(c) for c in checks]
    return {"state": state, "problems": problems,
            "headline": heads[0] if len(checks) == 1 else " | ".join(f"{c['name']}: {h}" for c, h in zip(checks, heads))}


def _item(id_: str, name: str, state: str, facts: list[str], actions: list[dict[str, Any]] | None = None,
          url: str | None = None) -> dict[str, Any]:
    out = {"id": id_, "name": name, "state": state, "facts": [f for f in facts if f], "actions": actions or []}
    if url:
        out["url"] = url
    return out


def details(entries: dict[str, dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
    out = []
    for name, entry in entries.items():
        c = check(name, entry, ctx)
        entry = _entries(ctx).get(name) or entry
        web = bw.endpoints(str(entry["url"]))[0]
        cloud = bw.is_cloud(web)
        items = []
        image = _image(entry, ctx)
        items.append(_item("server", "Bitwarden cloud" if cloud else f"Vaultwarden {_tag(image)}".strip(),
                           "up" if c["up"] else "down",
                           [web, "answers" if c["up"] else "not answering", entry.get("note") or ""], url=web))
        stage = c["stage"]
        hisho_ok = bool(entry.get("org_id"))
        items.append(_item("hisho", "Hisho's own account", "up" if hisho_ok else "warn" if cloud else "off",
                           [hisho_email(entry, ctx) if entry.get("hisho_password") else "not made yet",
                            f"owns the organization {ORG_NAME}, collection {COLLECTION}" if hisho_ok else
                            ("make a second free Bitwarden account for Hisho and give its email, master password "
                             "and API key (Account settings > Security > Keys) on this entry" if cloud else
                             "Hisho makes it by itself right after install"),
                            "its master password is a secret on the Core machine; nobody types it"],
                           [{"id": "setup", "label": "Set up now"}] if not hisho_ok else []))
        you_actions = [{"id": "invite", "label": "Invite me" if not entry.get("owner_email") else "Change email",
                        "ask": "Your Bitwarden account's email"}]
        if stage not in ("done", "need-email", "need-hisho"):
            you_actions.append({"id": "check", "label": "Check now"})
        if stage == "done":
            you_facts = [f"{entry['owner_email']} is in: open your vault, the {COLLECTION} collection is there"]
        elif stage == "need-email":
            you_facts = (["1. Use your Bitwarden account (or make one at bitwarden.com)." if cloud else
                          f"1. Make your account: open {web} and choose Create account. Your own email and a master "
                          "password only you know; Hisho never sees it.",
                          "2. Press Invite me and type that email. (Or type it first and make the account after.)",
                          "3. Hisho confirms you; the Hisho logins collection then shows in your vault."])
        else:
            you_facts = [c["message"]]
        if c["error"]:
            you_facts.append(f"last try: {c['error']}")
        items.append(_item("you", "Your account", "up" if stage == "done" else "warn", you_facts, you_actions,
                           url=None if stage == "done" or cloud else web))
        server_words = ("choose bitwarden.eu" if "bitwarden.eu" in web else "choose bitwarden.com") if cloud else \
            f"choose Self-hosted and type this server address: {web}"
        items.append(_item("apps", "Bitwarden apps", "up" if stage == "done" else "off",
                           ["Phone: Bitwarden from the App Store or Google Play",
                            "Browser: the Bitwarden extension (Chrome, Firefox, Edge, Safari)",
                            "Computer: the Bitwarden desktop app (Windows, macOS, Linux)",
                            f"In each, at sign-in (Logging in on / Accessing): {server_words}",
                            "Then sign in with your own email and master password."], url=APPS))
        saved = c["saved"]
        facts = [f"{len(saved)} saved by Hisho" + (f", last {ago(_now() - c['last_save'])} ago" if c["last_save"] else "")]
        if c["waiting"]:
            facts.append(f"{c['waiting']} waiting: you see them as soon as you have joined")
        if c["last_error"]:
            facts.append(f"last failed: {c['last_error'].get('name')}: {c['last_error'].get('error')}")
        facts += [f"{n}" + (f" ({v.get('service')}" + (f" on {v['machine']}" if v.get("machine") else "") + ")"
                            if v.get("service") else "") for n, v in sorted(saved.items())[:50]]
        items.append(_item("logins", f"Logins Hisho saved: {len(saved)}",
                           "warn" if c["last_error"] else "up" if saved else "off", facts))
        if managed(entry):
            closed = c["signups_closed"]
            items.append(_item("signups", "New accounts: " + ("closed" if closed else "open"),
                               "up" if closed else "warn",
                               ["only invited accounts can be made" if closed else
                                "open so Hisho's account and yours can be made; Hisho closes them once you are invited",
                                f"closed {datetime.fromtimestamp(closed, timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M %Z')}"
                                if closed else "",
                                f"admin page: {web}/admin (its token is the secret {entry['admin_token']})"
                                if entry.get("admin_token") else ""],
                               [] if closed else [{"id": "close-signups", "label": "Close sign-ups now",
                                                   "confirm": "Close sign-ups? Only invited accounts can be made "
                                                              "after this (Vaultwarden restarts, a few seconds)."}]))
            pin = pinned_image()
            behind = bool(image and pin and image != pin)
            items.append(_item("update", f"Update to {_tag(pin)}" if behind else "Version: Hisho's pinned one",
                               "warn" if behind else "up",
                               [f"running {image or '?'}", f"pinned {pin or '?'} (Hisho's deploy/vaultwarden/versions.env)",
                                "Update backs up first (~/backups/vaultwarden) and goes back if the new one doesn't answer"],
                               [{"id": "update", "label": "Update", "confirm": f"Back up, then update Vaultwarden to "
                                 f"{_tag(pin)}? It is down for about a minute."}] if behind else
                               [{"id": "backup", "label": "Back up now"}]))
        out.append({"title": name, "entry": name, "facts": [_headline(c)],
                    "state": "down" if not c["up"] else "ok" if stage == "done" and not c["last_error"] else "warn",
                    "items": items})
    return out


def test(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    url = str(entry.get("url") or "")
    try:
        web = bw.endpoints(url)[0]
    except bw.BitwardenError as exc:
        return {"ok": False, "error": str(exc)}
    if not bw.is_cloud(web) and not bw.Vault(web).alive():
        return {"ok": False, "error": f"{web} doesn't answer (is Vaultwarden running?)"}
    if not entry.get("hisho_password"):
        return {"ok": True, "message": "Bitwarden cloud: give Hisho's own account (email, master password, API key) "
                                       "to finish" if bw.is_cloud(web) else
                f"{web} answers; Hisho makes its own account there when you save"}
    try:
        v = bw.Vault(web, device_id=bw.device_id_for(f"{url}|{hisho_email(entry, ctx)}"))
        password = ctx.secret(entry["hisho_password"])
        if entry.get("hisho_client_id") and entry.get("hisho_client_secret"):
            v.login_api_key(str(entry["hisho_client_id"]), ctx.secret(entry["hisho_client_secret"]),
                            hisho_email(entry, ctx), password)
        else:
            v.login(hisho_email(entry, ctx), password)
    except bw.BitwardenError as exc:
        return {"ok": False, "error": f"Hisho's account can't sign in: {exc}"}
    return {"ok": True, "message": f"Hisho's account {hisho_email(entry, ctx)} signs in and unlocks"}


def act(entries: dict[str, dict[str, Any]], ctx: Any, entry: str, item: str, action: str) -> dict[str, Any]:
    e = entries.get(entry)
    if e is None:
        return {"ok": False, "error": f"no entry {entry}"}
    try:
        if action == "invite":
            email = str(getattr(ctx, "input", "") or "").strip().lower()
            if not EMAIL_RE.match(email):
                return {"ok": False, "error": "type your account's email, like you@example.com"}
            if email == hisho_email(e, ctx):
                return {"ok": False, "error": "that is Hisho's own account; type yours"}
            _set_entry(ctx, entry, {"owner_email": email})
            res = setup(entry, _entries(ctx).get(entry) or {**e, "owner_email": email}, ctx)
        elif action in ("check", "setup"):
            res = setup(entry, e, ctx)
        elif action == "close-signups":
            msg = close_signups(e, ctx)
            st = load_state(entry)
            st["signups_closed"] = _now()
            save_state(entry, st)
            return {"ok": True, "message": msg}
        elif action in ("update", "backup"):
            if not managed(e):
                return {"ok": False, "error": "only for a Vaultwarden Hisho installed"}
            res = _run(ctx, ["bash", str(installer()), f"--{action}"], timeout=900)
            text = (res.stdout or "").strip().splitlines()
            if res.returncode:
                return {"ok": False, "error": (res.stderr or "\n".join(text)).strip()[-300:]}
            _journal(f"vaultwarden-{action}", {"entry": entry, "said": text[-1:] or []})
            return {"ok": True, "message": text[-1] if text else "done"}
        else:
            return {"ok": False, "error": f"unknown action {action}"}
    except bw.BitwardenError as exc:
        return {"ok": False, "error": str(exc)}
    words = "; ".join(res.get("done") or [])
    if res.get("error"):
        return {"ok": False, "error": res["error"]}
    return {"ok": True, "message": (words + ". " if words else "") + res["message"]}
