# Bitwarden / Vaultwarden (Hisho add-on)

## What it does

Passwords kept safe. Every login Hisho makes or is given (a new machine's admin password, a service
account, an app's API login) goes into **your own password vault**, in a collection called
**Hisho logins** that your Bitwarden apps show next to your own items: on your phone, in your
browser, on your computer.

- **Hisho has its own account** on the vault, with a long master password it made itself (kept as a
  secret on the Core machine; nobody types it). That account owns an organization **Hisho** with the
  collection **Hisho logins**.
- **Your account is invited and confirmed.** You give the email of your own Bitwarden account; Hisho
  invites it, and once you have joined, confirms you. Confirming is Bitwarden's step that hands you
  the organization's key, encrypted to your account's own public key, so only your apps can open it.
- **Encrypted before it leaves Hisho.** Hisho encrypts every item the way Bitwarden's own apps do
  (AES-256 with HMAC, the organization key shared with RSA-OAEP). The server stores only ciphertext.
- **Changed in place.** Saving a login of the same name again updates the item Hisho made (marked with
  a "Made by: Hisho" field). Your own items are never touched, even with the same name.
- **The vault itself.** No vault yet? **Install in Hisho** runs **Vaultwarden** (a small, open source,
  Bitwarden-compatible server) on the Core machine: Docker, data in `~/vaultwarden`, listening on
  127.0.0.1 only and published on your tailnet at `https://<Core machine>:5443` (never the LAN, never
  the internet). New accounts are allowed only until your invite is out; then Hisho closes sign-ups.
  The image is pinned (`deploy/vaultwarden/versions.env` in Hisho); **Update** backs up first and goes
  back to the old version if the new one doesn't answer. Hisho's Core backup includes it.
- **Or Bitwarden cloud.** If you already use bitwarden.com (US) or bitwarden.eu (EU), Hisho works with
  it too: make a second free account for Hisho, and the free two-person organization holds Hisho's
  logins for you.

## What it needs

- You need:
  - A Bitwarden account of your own (Hisho can run the vault for you: Vaultwarden on the Core machine)
  - The Bitwarden app on your phone, browser or computer, to see the logins
- Runs on: the Core machine, inside Hisho Core
- One entry per Password vault, each with:
  - `url` (url, required)
  - `owner_email` (str, optional)
  - `hisho_email` (str, optional)
  - `hisho_password` (password, kept as a local secret, optional)
  - `hisho_client_id` (str, optional)
  - `hisho_client_secret` (password, kept as a local secret, optional)
  - `admin_token` (password, kept as a local secret, optional)
  - `org_id` (str, optional)
  - `collection_id` (str, optional)
  - `data_dir` (str, optional)
  - `container` (str, optional)
  - `note` (str, optional)

## How to install

On the dashboard: **Add-ons > Store > Bitwarden / Vaultwarden > Install**. Or from a terminal:

```bash
hisho addon install vaultwarden
```

Hisho takes the newest version from this repository, copies it to the machine it runs on and turns
it on. Updates show as **Update available** on its Store card; **Roll back** returns to the version
before.

## How to use

On its page (**Add-ons > Bitwarden / Vaultwarden**):

1. **Install Vaultwarden** (the Install in Hisho button), or, if you use Bitwarden cloud, **+ add** an
   entry with `https://vault.bitwarden.com` (or `.eu`) and Hisho's own account (below).
2. **Make your account.** Open the vault's address (the page links it) and choose **Create account**:
   your own email and a master password only you know. Hisho never sees it.
3. **Invite me.** Press it and type that email. Hisho invites your account.
   (You can also type the email first and make the account after: the invite lets that one email make
   an account even once sign-ups are closed.)
4. **Accept the invite.** On Vaultwarden there is no email: making or already having the account is
   accepting. On Bitwarden cloud, open the invite email and choose **Join organization**.
5. **Hisho confirms you**, within a minute (or press **Check now**). Done: the **Hisho logins**
   collection is in your vault.
6. **Your apps.** Install Bitwarden on your phone (App Store, Google Play), the browser extension
   (Chrome, Firefox, Edge, Safari) and the desktop app (https://bitwarden.com/download/). At sign-in,
   under **Logging in on**, choose **Self-hosted** and type the server address the page shows
   (`https://<Core machine>:5443`); on Bitwarden cloud choose bitwarden.com or bitwarden.eu. Sign in
   with your own email and master password.

The card says how many logins Hisho saved, how many wait for you to join, and when it last saved one.
If it can't save one, Needs you says so.

**Bitwarden cloud: Hisho's own account.** Make a second free account at bitwarden.com (an address of
yours that gets mail, like `you+hisho@example.com`) with a new long master password. Signed in as
that account, open **Account settings > Security > Keys > View API key**. Give the entry Hisho's email,
master password, the API key's `client_id` and `client_secret`. Hisho signs in with the API key (no
captcha, no new-device email) and unlocks with the master password.

## Settings

One entry per vault, on its page or in `~/Hisho/System/Config/Addons/vaultwarden.yaml`. Install in
Hisho fills it for you:

```yaml
entries:
  main:
    url: https://kihon.example.ts.net:5443   # the vault (Bitwarden cloud: https://vault.bitwarden.com)
    owner_email: you@example.com             # your account (Invite me fills it)
    hisho_email: hisho@kihon.local           # Hisho's own account (made by Hisho on Vaultwarden)
    hisho_password: HISHO_ADDON_VAULTWARDEN_MAIN_HISHO_PASSWORD   # a secret's NAME, never its value
    admin_token: HISHO_ADDON_VAULTWARDEN_MAIN_ADMIN_TOKEN         # Vaultwarden's admin page (/admin)
    data_dir: ~/vaultwarden                  # the Vaultwarden Hisho installed
    container: vaultwarden
    # org_id, collection_id: filled by Hisho
```

Other parts of Hisho save logins through `save_login(login, ctx)` in `provider.py` (the manifest's
`login_store: true`): `login` is `{name, service, machine, url, username, password, note}`; it returns
`{"ok", "message", "id"}`. The password never reaches a message, a log or the journal.

Vaultwarden's own settings are in `~/vaultwarden/config/vaultwarden.env` (0600; read at every start).
Changing a setting on its admin page writes `~/vaultwarden/data/config.json`, which wins over that file.

## How to remove

**Add-ons > Store > Bitwarden / Vaultwarden > Remove**, or `hisho addon remove vaultwarden`. Your
settings file stays, so installing it again picks up where you left off. Removing Vaultwarden itself
(Remove on its Install in Hisho card) stops it and keeps `~/vaultwarden`; your logins stay in it, and
in every Bitwarden app that has synced them.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
