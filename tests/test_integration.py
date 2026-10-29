"""Against a real Vaultwarden (the pinned image, started by Hisho's own install.sh on a test port), only when asked:

    HISHO_TEST_VAULTWARDEN=1 ~/code/hisho/.venv/bin/python -m pytest -q -s tests/test_integration.py

Install-like setup (install.sh with test paths, no tailnet), the admin token's hash, Hisho's own account, the Hisho
organization and its collection, a test owner account, invite, accept, confirm, sign-ups closed, save_login (made
and changed in place), and the owner's account opening the item with its own keys. The container and its data are
removed afterwards. Prints the container's memory and disk use."""
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("HISHO_TEST_VAULTWARDEN") != "1" or not shutil.which("docker"),
                                reason="real Vaultwarden test: set HISHO_TEST_VAULTWARDEN=1 (needs Docker)")

PORT = int(os.environ.get("HISHO_TEST_VAULTWARDEN_PORT") or 18224)
NAME = "hisho-vw-itest"
URL = f"http://127.0.0.1:{PORT}"


def _repo() -> Path:
    import hisho
    return Path(hisho.__file__).resolve().parents[2]


def _env(d: Path, backups: Path) -> dict:
    return {**os.environ, "VW_DIR": str(d), "VW_PORT": str(PORT), "VW_CONTAINER": NAME, "VW_DOMAIN": URL,
            "VW_SERVE": "0", "VW_BACKUPS": str(backups), "HISHO_REPO": str(_repo()), "HISHO_COMPANION_DATA_DIR": str(d)}


@pytest.fixture(scope="module")
def vaultwarden(tmp_path_factory):
    d = tmp_path_factory.mktemp("vw") / "vaultwarden"
    backups = d.parent / "backups"
    script = _repo() / "deploy" / "vaultwarden" / "install.sh"
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    t0 = time.time()
    res = subprocess.run(["bash", str(script)], env=_env(d, backups), capture_output=True, text=True, timeout=600)
    from hisho import addons
    fills, said = addons.install_fills(res.stdout, "HISHO_ENTRY")
    print(f"\n[install.sh exit {res.returncode} in {time.time() - t0:.1f} s]\n{said}")
    assert res.returncode == 0, res.stderr[-2000:]
    try:
        yield {"dir": d, "backups": backups, "fills": fills, "script": script}
    finally:
        subprocess.run(["bash", str(script), "--remove"], env=_env(d, backups), capture_output=True, timeout=300)
        subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
        shutil.rmtree(d.parent, ignore_errors=True)
        left = subprocess.run(["docker", "ps", "-a", "--filter", f"name={NAME}", "--format", "{{.Names}}"],
                              capture_output=True, text=True).stdout.strip()
        print(f"[cleanup: container left: {left or 'none'}; data folder gone: {not d.exists()}]")


class RealCtx:
    def __init__(self, addon):
        from hisho import addons
        self._c = addons.Context(addon, resolve=lambda n: os.environ[n])
        self.addon, self.fleet, self.input = addon, self._c.fleet, ""

    def secret(self, name):
        return self._c.secret(name)

    def run(self, cmd, timeout=30, env=None):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})


def _admin_login(token: str) -> int:
    req = urllib.request.Request(URL + "/admin", data=urllib.parse.urlencode({"token": token}).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as resp:
            return resp.status if "VW_ADMIN" in (resp.headers.get("Set-Cookie") or "") else -resp.status
    except urllib.error.HTTPError as exc:
        return exc.code if "VW_ADMIN" in (exc.headers.get("Set-Cookie") or "") else -exc.code


def test_the_whole_flow_on_a_real_vaultwarden(vaultwarden, addon, fleet, monkeypatch, tmp_path):
    from hisho import addons
    monkeypatch.setenv("HISHO_STATE_DIR", str(tmp_path / "state"))
    prov = addons.provider(addon)
    bw = prov.bw
    d, fills = vaultwarden["dir"], vaultwarden["fills"]
    step = lambda s: print(f"  ok: {s}")   # noqa: E731

    # install: settings 0600, only the hash in them, the plain admin token handed over (and it opens /admin)
    env = (d / "config" / "vaultwarden.env").read_text()
    assert oct((d / "config" / "vaultwarden.env").stat().st_mode & 0o777) == "0o600"
    assert "ADMIN_TOKEN='$argon2id$" in env and fills["admin_token"] not in env and not (d / ".admin-token").exists()
    assert fills["container"] == NAME
    assert _admin_login(fills["admin_token"]) in (200, 303) and _admin_login("wrong-token") < 0
    step("install.sh: pinned image up on 127.0.0.1, admin token argon2-hashed, plain token handed to Hisho, /admin opens with it")
    image = subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}} {{.HostConfig.PortBindings}}", NAME],
                           capture_output=True, text=True).stdout.strip()
    assert image.startswith(prov.pinned_image()) and "127.0.0.1" in image

    # the entry Install in Hisho leaves
    addons.set_entry(addon, "main", {"url": URL, "data_dir": str(d), "container": fills["container"],
                                     "admin_token": fills["admin_token"]})
    ctx = RealCtx(addon)
    res = prov.setup("main", addons.entries(addon)["main"], ctx)
    assert res["stage"] == "need-email", res
    e = addons.entries(addon)["main"]
    step(f"Hisho's own account {e['hisho_email']} registered, organization Hisho + collection Hisho logins made: {res['done']}")
    hv = bw.Vault(URL)
    hv.login(e["hisho_email"], os.environ[e["hisho_password"]])
    assert [o["name"] for o in hv.organizations()] == ["Hisho"]
    assert hv.collections(e["org_id"]) == [{"id": e["collection_id"], "name": "Hisho logins"}]

    # the owner makes an account (sign-ups still open), then Invite me
    owner_pw = "owner test master password 1"
    bw.Vault(URL).register("owner@example.test", owner_pw, name="Owner")
    ctx.input = "owner@example.test"
    res = prov.act(addons.entries(addon), ctx, "main", "you", "invite")
    assert res["ok"] and "confirmed owner@example.test" in res["message"], res
    step(f"invite -> accepted (no mail: an existing account joins at once) -> confirmed: {res['message']}")
    assert "SIGNUPS_ALLOWED=false" in (d / "config" / "vaultwarden.env").read_text()
    with pytest.raises(bw.BitwardenError, match="not allowed"):
        bw.Vault(URL).register("stranger@example.test", "stranger password 123")
    step("sign-ups closed by Hisho (settings file + container restart): a stranger can't make an account")

    # save_login: made, then changed in place
    login = {"name": "Lab server root", "service": "proxmox", "machine": "lab-server", "url": "https://192.0.2.10:8006",
             "username": "root@pam", "password": "first-Pass-1", "note": "test login"}
    r1 = prov.save_login(login, ctx)
    r2 = prov.save_login({**login, "password": "second-Pass-2"}, ctx)
    assert r1["ok"] and r2["ok"] and r1["id"] == r2["id"], (r1, r2)
    step(f"save_login: {r1['message']} / {r2['message']} (same item {r1['id']})")

    # the owner's own account opens it with its own keys
    ov = bw.Vault(URL)
    ov.login("owner@example.test", owner_pw)
    items = ov.org_items(e["org_id"])
    assert [(i["name"], i["username"], i["password"]) for i in items] == [("Lab server root", "root@pam", "second-Pass-2")]
    assert items[0]["fields"] == {"Made by": "Hisho", "Service": "proxmox", "Machine": "lab-server"}
    assert items[0]["uris"] == ["https://192.0.2.10:8006"] and items[0]["collections"] == [e["collection_id"]]
    step("the owner's account decrypts the item (organization key from its confirm, RSA-OAEP to its public key)")

    # invited before the account exists: Vaultwarden makes a stub; signing up (sign-ups closed) joins; Hisho confirms
    ctx.input = "late@example.test"
    res = prov.act(addons.entries(addon), ctx, "main", "you", "invite")
    assert res["ok"] and prov.load_state("main")["stage"] == "waiting", res
    bw.Vault(URL).register("late@example.test", "late test master password 1")
    res = prov.setup("main", addons.entries(addon)["main"], ctx)
    assert res["stage"] == "done", res
    lv = bw.Vault(URL)
    lv.login("late@example.test", "late test master password 1")
    assert [i["password"] for i in lv.org_items(e["org_id"])] == ["second-Pass-2"]
    step("invite first, account after (with sign-ups closed): joined, confirmed by Hisho, item readable")

    # the page and the card
    s = prov.summary(addons.entries(addon), ctx)
    assert s["state"] == "ok" and s["headline"].startswith("1 login saved"), s
    det = prov.details(addons.entries(addon), ctx)[0]
    assert det["state"] == "ok", det
    step(f"card: {s['headline']}")

    # backup: an online copy of the database + keys and settings
    res = subprocess.run(["bash", str(vaultwarden["script"]), "--backup"], env=_env(d, vaultwarden["backups"]),
                         capture_output=True, text=True, timeout=300)
    assert res.returncode == 0, res.stderr
    tar = sorted(vaultwarden["backups"].glob("vaultwarden-*.tar.gz"))[-1]
    assert oct(tar.stat().st_mode & 0o777) == "0o600"
    out = tmp_path / "restore"
    with tarfile.open(tar) as t:
        t.extractall(out, filter="data")
    users = sqlite3.connect(out / "db.sqlite3").execute("select count(*) from users").fetchone()[0]
    assert users >= 3
    with tarfile.open(out / "files.tar.gz") as t:
        names = t.getnames()
    assert "data/rsa_key.pem" in names and "config/vaultwarden.env" in names
    step(f"install.sh --backup: {tar.name}, {tar.stat().st_size} bytes, database with {users} accounts, keys and settings")

    # how much it takes on this machine
    stats = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", NAME],
                           capture_output=True, text=True).stdout.strip()
    du = subprocess.run(["du", "-sh", str(d / "data")], capture_output=True, text=True).stdout.split()[0]
    size = subprocess.run(["docker", "image", "inspect", "-f", "{{.Size}}", prov.pinned_image()],
                          capture_output=True, text=True).stdout.strip()
    print(f"  memory: {stats}; data folder: {du}; image: {int(size) / 1e6:.0f} MB")
    print(json.dumps({"memory": stats, "data": du, "image_mb": round(int(size) / 1e6)}))
