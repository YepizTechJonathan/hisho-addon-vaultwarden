"""The Vaultwarden add-on's setup, its save_login contract and its page, against a fake server that behaves like
Vaultwarden without mail (bitwarden.py's crypto is tested in test_bitwarden.py; the real server in
test_integration.py)."""
import itertools
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parents[1]
URL = "https://kihon.example.ts.net:5443"


class Server:
    def __init__(self):
        self.accounts = {}      # email -> {password, user_id}
        self.orgs = {}          # id -> {name, members: [...], collections: {id: name}}
        self.items = {}         # id -> item
        self.signups = True
        self.up = True
        self.ids = (f"id-{n}" for n in itertools.count(1))


def fake_vault(server, bw):
    class FakeVault:
        def __init__(self, url, http=None, device_id=None, timeout=30):
            self.url, self.email, self.user_id = url, "", ""

        def alive(self):
            return server.up

        def _stub(self, email):
            return email in server.accounts and server.accounts[email]["password"] is None

        def registration_token(self, email, name=""):
            if not (server.signups or self._stub(email)):
                raise bw.BitwardenError("Registration not allowed or user already exists", 400)
            return "token"

        def register(self, email, password, name="Hisho", hint=None):
            if email in server.accounts and not self._stub(email):
                raise bw.BitwardenError("Registration not allowed or user already exists", 400)
            self.registration_token(email)
            acct = server.accounts.setdefault(email, {"user_id": next(server.ids)})
            acct["password"] = password
            for org in server.orgs.values():     # Vaultwarden: making the account accepts its invites
                for m in org["members"]:
                    if m["email"] == email and m["status"] == bw.INVITED:
                        m["status"] = bw.ACCEPTED

        def login(self, email, password):
            acct = server.accounts.get(email)
            if not acct or acct["password"] != password:
                raise bw.BitwardenError("Username or password is incorrect. Try again", 400)
            self.email, self.user_id = email, acct["user_id"]

        def login_api_key(self, client_id, secret, email, password):
            self.login(email, password)

        def organizations(self):
            return [{"id": oid, "name": o["name"], "type": m["type"]} for oid, o in server.orgs.items()
                    for m in o["members"] if m["user_id"] == self.user_id and m["status"] == bw.CONFIRMED]

        def create_org(self, name, collection, billing):
            oid, cid = next(server.ids), next(server.ids)
            server.orgs[oid] = {"name": name, "collections": {cid: collection}, "members": [
                {"id": next(server.ids), "user_id": self.user_id, "email": self.email, "status": bw.CONFIRMED,
                 "type": bw.OWNER}]}
            return oid, None

        def collections(self, org):
            return [{"id": k, "name": v} for k, v in server.orgs[org]["collections"].items()]

        def create_collection(self, org, name):
            cid = next(server.ids)
            server.orgs[org]["collections"][cid] = name
            return cid

        def members(self, org):
            return [dict(m) for m in server.orgs[org]["members"]]

        def invite(self, org, email, collection_id, kind=bw.ADMIN):
            acct = server.accounts.get(email)
            if acct is None:                   # no mail: a stub account waits for its sign-up
                acct = server.accounts[email] = {"user_id": next(server.ids), "password": None}
            server.orgs[org]["members"].append(
                {"id": next(server.ids), "user_id": acct["user_id"], "email": email, "type": kind,
                 "status": bw.ACCEPTED if acct["password"] else bw.INVITED})

        def confirm(self, org, member):
            m = next(x for x in server.orgs[org]["members"] if x["id"] == member["id"])
            assert m["status"] == bw.ACCEPTED, "only an accepted member can be confirmed"
            m["status"] = bw.CONFIRMED

        def org_items(self, org):
            return [dict(i) for i in server.items.values() if i["org"] == org]

        def put_login(self, org, col, item, item_id=None, revision=None):
            item_id = item_id or next(server.ids)
            server.items[item_id] = {**item, "id": item_id, "org": org, "collections": [col], "revision": "r"}
            return item_id
    return FakeVault


@pytest.fixture
def prov(addon, monkeypatch, tmp_path):
    from hisho import addons
    monkeypatch.setenv("HISHO_STATE_DIR", str(tmp_path / "state"))
    p = addons.provider(addon)
    server = Server()
    monkeypatch.setattr(p.bw, "Vault", fake_vault(server, p.bw))
    monkeypatch.setattr(p, "_sessions", {})
    p.server = server
    before = set(os.environ)
    yield p
    for k in set(os.environ) - before:   # local secrets the add-on saved during the test
        os.environ.pop(k, None)


class Ctx:
    """Hisho's Context, secrets from the local secrets file it writes, commands recorded."""

    def __init__(self, addon):
        from hisho import addons
        self._c = addons.Context(addon, resolve=lambda n: os.environ[n])
        self.addon, self.fleet, self.input, self.ran = addon, self._c.fleet, "", []

    def secret(self, name):
        return self._c.secret(name)

    def run(self, cmd, timeout=30, env=None):
        self.ran.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


def installed(addon, tmp_path, **more):
    """What Install in Hisho leaves: the entry from the manifest's companion entry: + the install's HISHO_ENTRY lines."""
    from hisho import addons
    data = tmp_path / "vaultwarden"
    (data / "config").mkdir(parents=True)
    env = data / "config" / "vaultwarden.env"
    env.write_text("DOMAIN=" + URL + "\nSIGNUPS_ALLOWED=true\nADMIN_TOKEN='$argon2id$v=19$m=65540,t=3,p=4$x$y'\n")
    env.chmod(0o600)
    addons.set_entry(addon, "main", {"url": URL, "data_dir": str(data), "container": "vaultwarden",
                                     "admin_token": "plain-admin-token", **more})
    return env


def test_the_manifest_is_valid_and_install_in_hisho_runs_hishos_own_install():
    from hisho import addons, companion
    m = yaml.safe_load((HERE / "addon.yaml").read_text())
    assert addons.validate_manifest(m) == []
    c = m["companion"]
    assert companion.problems(addons.Addon("vaultwarden", HERE, m)) == []
    assert c["detect"]["containers"] == ["vaultwarden"] and c["detect"]["entry"] == "url"
    assert c["entry"]["url"] == "https://{core_dns}:5443" and c["data_dir"] == "~/vaultwarden"
    assert "deploy/vaultwarden/install.sh" in (HERE / c["install"]).read_text()
    assert "install.sh\" --remove" in (HERE / c["uninstall"]).read_text()
    assert m["login_store"] is True and m["kind"] == "integration"
    assert set(m["entry_form"]) <= set(m["entry_schema"]) and set(m["help"]) <= set(m["entry_schema"])


def test_the_install_admin_token_is_kept_as_a_secret_not_in_the_entry(addon, prov, tmp_path):
    from hisho import addons
    installed(addon, tmp_path)
    e = addons.entries(addon)["main"]
    assert e["admin_token"] == "HISHO_ADDON_VAULTWARDEN_MAIN_ADMIN_TOKEN"
    assert "plain-admin-token" not in addons.config_path("vaultwarden").read_text()


def test_setup_makes_hishos_account_and_the_org_then_asks_for_your_email(addon, prov, tmp_path):
    from hisho import addons
    installed(addon, tmp_path)
    ctx = Ctx(addon)
    res = prov.setup("main", addons.entries(addon)["main"], ctx)
    assert res["stage"] == "need-email", res
    e = addons.entries(addon)["main"]
    assert e["hisho_email"] == "hisho@kihon.local"
    assert e["hisho_password"] == "HISHO_ADDON_VAULTWARDEN_MAIN_HISHO_PASSWORD"   # a secret's name, not the value
    pw = os.environ[e["hisho_password"]]
    assert len(pw) == 40 and pw not in addons.config_path("vaultwarden").read_text()
    assert prov.server.accounts["hisho@kihon.local"]["password"] == pw
    org = prov.server.orgs[e["org_id"]]
    assert org["name"] == "Hisho" and org["collections"][e["collection_id"]] == "Hisho logins"
    assert "Hisho logins" in " ".join(res["done"])
    # again: nothing new is made
    again = prov.setup("main", addons.entries(addon)["main"], ctx)
    assert again["done"] == [] and len(prov.server.orgs) == 1


def test_invite_me_with_an_existing_account_confirms_at_once_and_closes_signups(addon, prov, tmp_path):
    from hisho import addons
    env = installed(addon, tmp_path)
    ctx = Ctx(addon)
    prov.setup("main", addons.entries(addon)["main"], ctx)
    prov.server.accounts["me@example.com"] = {"user_id": "u-me", "password": "mine"}
    ctx.input = "Me@Example.com "
    res = prov.act(addons.entries(addon), ctx, "main", "you", "invite")
    assert res["ok"], res
    assert "invited me@example.com" in res["message"] and "confirmed me@example.com" in res["message"]
    org = prov.server.orgs[addons.entries(addon)["main"]["org_id"]]
    me = next(m for m in org["members"] if m["email"] == "me@example.com")
    assert me["status"] == prov.bw.CONFIRMED
    # sign-ups closed: the settings file changed (still 0600) and the container restarted
    assert "SIGNUPS_ALLOWED=false" in env.read_text() and "SIGNUPS_ALLOWED=true" not in env.read_text()
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert ["docker", "restart", "vaultwarden"] in ctx.ran
    assert prov.load_state("main")["stage"] == "done"


def test_invite_before_the_account_exists_waits_then_confirms_when_it_is_made(addon, prov, tmp_path):
    from hisho import addons
    installed(addon, tmp_path)
    ctx = Ctx(addon)
    ctx.input = "late@example.com"
    res = prov.act(addons.entries(addon), ctx, "main", "you", "invite")
    assert res["ok"] and "Create account with late@example.com" in res["message"], res
    assert prov.load_state("main")["stage"] == "waiting"
    prov.server.signups = False     # closed by then; the invite still lets that one email sign up
    prov.bw.Vault(URL).register("late@example.com", "their-own")
    res = prov.setup("main", addons.entries(addon)["main"], ctx)
    assert res["stage"] == "done" and "confirmed late@example.com" in " ".join(res["done"])


def test_save_login_writes_into_the_collection_and_changes_only_its_own_items_in_place(addon, prov, tmp_path):
    from hisho import addons
    installed(addon, tmp_path)
    ctx = Ctx(addon)
    prov.setup("main", addons.entries(addon)["main"], ctx)
    e = addons.entries(addon)["main"]
    # the owner's own item of the same name: never touched
    prov.server.items["mine"] = {"id": "mine", "org": e["org_id"], "name": "Lab server root", "fields": {},
                                 "password": "owner's", "collections": [e["collection_id"]]}
    login = {"name": "Lab server root", "service": "proxmox", "machine": "lab-server", "url": "https://192.0.2.10:8006",
             "username": "root@pam", "password": "first-pass", "note": "made by Hisho's Proxmox setup"}
    r1 = prov.save_login(login, ctx)
    assert r1["ok"] and r1["id"] and r1["message"].startswith("Saved Lab server root"), r1
    r2 = prov.save_login({**login, "password": "second-pass"}, ctx)
    assert r2["ok"] and r2["id"] == r1["id"] and r2["message"].startswith("Updated"), r2
    item = prov.server.items[r1["id"]]
    assert item["password"] == "second-pass" and item["username"] == "root@pam"
    assert item["uris"] == ["https://192.0.2.10:8006"] and item["notes"] == "made by Hisho's Proxmox setup"
    assert item["fields"] == {"Made by": "Hisho", "Service": "proxmox", "Machine": "lab-server"}
    assert item["collections"] == [e["collection_id"]]
    assert prov.server.items["mine"]["password"] == "owner's"
    st = prov.load_state("main")
    assert list(st["saved"]) == ["Lab server root"] and st["last_save"]
    # never a password in the journal or the state
    journal = "".join(p.read_text() for p in (Path(os.environ["HISHO_ROOT"]) / "System" / "Journal").rglob("*") if p.is_file())
    assert "vaultwarden-login-saved" in journal
    for secret in ("first-pass", "second-pass"):
        assert secret not in journal and secret not in json.dumps(st)



def test_save_login_with_cores_login_shape_keeps_one_item_per_key(addon, prov, tmp_path):
    """Core sends name "login" for every service; its stable key tells them apart."""
    from hisho import addons
    installed(addon, tmp_path)
    ctx = Ctx(addon)
    prov.setup("main", addons.entries(addon)["main"], ctx)
    base = {"name": "login", "machine": "souko", "username": "jonathan", "note": "What: test"}
    sem = prov.save_login({**base, "key": "HISHO_SEMAPHORE_SOUKO_LOGIN", "service": "semaphore", "title": "Semaphore",
                           "password": "s1"}, ctx)
    fj = prov.save_login({**base, "key": "HISHO_FORGEJO_SOUKO_LOGIN", "service": "forgejo", "title": "Forgejo",
                          "password": "f1"}, ctx)
    key = prov.save_login({"name": "encryption_key", "key": "HISHO_INFISICAL_SOUKO_ENCRYPTION_KEY", "machine": "souko",
                           "service": "infisical", "title": "Infisical", "username": "", "password": "k1"}, ctx)
    assert len({sem["id"], fj["id"], key["id"]}) == 3
    names = {prov.server.items[r["id"]]["name"] for r in (sem, fj, key)}
    assert names == {"Semaphore (souko)", "Forgejo (souko)", "Infisical encryption key (souko)"}
    again = prov.save_login({**base, "key": "HISHO_SEMAPHORE_SOUKO_LOGIN", "service": "semaphore", "title": "Semaphore",
                             "password": "s2"}, ctx)
    assert again["id"] == sem["id"] and prov.server.items[sem["id"]]["password"] == "s2"
    assert prov.server.items[sem["id"]]["fields"]["Hisho key"] == "HISHO_SEMAPHORE_SOUKO_LOGIN"

def test_save_login_says_why_when_it_cant_and_never_shows_the_password(addon, prov, tmp_path):
    from hisho import addons
    ctx = Ctx(addon)
    assert prov.save_login({"name": "x", "password": "p"}, ctx) == {
        "ok": False, "message": "Your password vault isn't set up yet (Add-ons > Bitwarden / Vaultwarden): nothing was saved"}
    assert not prov.save_login({"name": "x"}, ctx)["ok"]
    installed(addon, tmp_path)
    prov.setup("main", addons.entries(addon)["main"], ctx)

    def boom(*a, **k):
        raise prov.bw.BitwardenError("server said no to leaky-pass")
    prov.bw.Vault.put_login = boom
    res = prov.save_login({"name": "db", "password": "leaky-pass"}, ctx)
    assert not res["ok"] and "leaky-pass" not in res["message"] and "***" in res["message"]
    assert "leaky-pass" not in json.dumps(prov.load_state("main"))
    s = prov.summary(addons.entries(addon), ctx)
    assert any("couldn't save db" in p["title"] for p in s["problems"])


def test_bitwarden_cloud_waits_for_hishos_own_account_and_never_registers_one(addon, prov, tmp_path):
    from hisho import addons
    addons.set_entry(addon, "main", {"url": "https://vault.bitwarden.com", "owner_email": "me@example.com"})
    ctx = Ctx(addon)
    res = prov.setup("main", addons.entries(addon)["main"], ctx)
    assert res["stage"] == "need-hisho" and not prov.server.accounts
    # given its account (API key sign-in): org, invite; cloud mails the invite, so it waits for the owner
    prov.server.accounts["hisho+me@example.com"] = {"user_id": "u-h", "password": "hp"}
    prov.server.accounts["me@example.com"] = {"user_id": "u-me", "password": None}   # (not signed up here)
    addons.set_entry(addon, "main", {"hisho_email": "hisho+me@example.com", "hisho_password": "hp",
                                     "hisho_client_id": "user.abc", "hisho_client_secret": "cs"}, merge=True)
    res = prov.setup("main", addons.entries(addon)["main"], ctx)
    assert res["stage"] == "waiting" and "Bitwarden emailed me@example.com" in res["message"], res
    assert ctx.ran == []          # no sign-up switch, no docker: not ours


def test_the_page_walks_the_owner_through_and_the_card_counts(addon, prov, tmp_path, monkeypatch):
    from hisho import addons
    installed(addon, tmp_path)
    ctx = Ctx(addon)
    monkeypatch.setattr(prov, "_image", lambda e, c: "vaultwarden/server:1.37.3@sha256:old")
    d = prov.details(addons.entries(addon), ctx)[0]
    items = {i["id"]: i for i in d["items"]}
    assert set(items) >= {"server", "hisho", "you", "apps", "logins", "signups", "update"}
    you = items["you"]
    assert you["actions"][0] == {"id": "invite", "label": "Invite me", "ask": "Your Bitwarden account's email"}
    assert any(URL in f and "Create account" in f for f in you["facts"]) and you["url"] == URL
    assert any(f"type this server address: {URL}" in f for f in items["apps"]["facts"])
    assert items["update"]["actions"][0]["id"] == "update" and "1.37.4" in items["update"]["name"]
    assert items["signups"]["actions"][0]["id"] == "close-signups"
    s = prov.summary(addons.entries(addon), ctx)
    assert s["state"] == "ok" and any(p["title"] == "Finish setting up your password vault" and p.get("quiet")
                                      for p in s["problems"])
    prov.save_login({"name": "a", "password": "p"}, ctx)
    assert s["headline"].startswith("0 logins saved")
    s = prov.summary(addons.entries(addon), ctx)
    assert "1 login saved" in s["headline"] and "1 waiting for you to join" in s["headline"]
    prov.server.up = False
    s = prov.summary(addons.entries(addon), ctx)
    assert s["state"] == "down" and s["problems"][0]["title"] == "Your password vault isn't answering"


def test_invite_refuses_a_non_email_and_hishos_own(addon, prov, tmp_path):
    from hisho import addons
    installed(addon, tmp_path)
    ctx = Ctx(addon)
    ctx.input = "not an email"
    assert not prov.act(addons.entries(addon), ctx, "main", "you", "invite")["ok"]
    ctx.input = "hisho@kihon.local"
    assert "Hisho's own" in prov.act(addons.entries(addon), ctx, "main", "you", "invite")["error"]


def test_update_and_backup_run_hishos_install_script(addon, prov, tmp_path):
    from hisho import addons
    installed(addon, tmp_path)
    ctx = Ctx(addon)
    res = prov.act(addons.entries(addon), ctx, "main", "update", "update")
    assert res["ok"]
    assert ctx.ran[-1][0] == "bash" and ctx.ran[-1][1].endswith("deploy/vaultwarden/install.sh") and ctx.ran[-1][2] == "--update"
    prov.act(addons.entries(addon), ctx, "main", "update", "backup")
    assert ctx.ran[-1][2] == "--backup"
    assert Path(ctx.ran[-1][1]).is_file()     # Hisho's installer is really there
