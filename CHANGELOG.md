# Changelog

## 0.1.1

- Logins are matched by Hisho's stable key, so each service keeps its own item ("Semaphore (souko)", "Infisical encryption key (souko)").

## 0.1.0

- First version: passwords kept safe. Install in Hisho runs Vaultwarden on the Core machine (pinned image, tailnet
  only, admin token hashed and kept as a secret). Hisho makes its own account and an organization "Hisho" with the
  collection "Hisho logins", invites your account, confirms it (the organization key encrypted to your public key),
  closes sign-ups, and from then on saves every login it is given there (`save_login`, `login_store: true`),
  changing in place the items it made. Bitwarden's encryption is done here; the server never sees a password.
  Bitwarden cloud works the same with a second free account for Hisho (API key sign-in). Update and backup buttons
  for the Vaultwarden Hisho installed.
