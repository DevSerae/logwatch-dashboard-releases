# Admin commands

Run these on the board's VM, from the install directory. Run `setup.py` as the `logwatch` user (as root, 2.3.0+ keeps
`secrets/secrets.env` readable by the board, but files it creates elsewhere may not be).

```bash
cd /opt/logwatch-dashboard
```

## Users, roles and sign-in

Since 2.3.0 the board has **multiple users**, each with a role:

- **admin**: everything, including users and sign-in settings.
- **auditor**: view only. They can open every page and log but can't change anything. They can still manage their own
  password and MFA.

In the board, **Settings → Account** has your password, MFA and sessions. Admins also get **Users & sign-in** (`/users`)
for users, required MFA and SSO. The same tasks work from the VM with `setup.py user`, which runs inside the board
container. Changes apply at once, with no restart. None of these commands need the old password, so they also work
when you're locked out.

| Task | Command |
|---|---|
| List users | `sudo -u logwatch python3 setup.py user list` |
| Add a user (prompts for the password) | `sudo -u logwatch python3 setup.py user add alice --role auditor` |
| Add an SSO-only user | `sudo -u logwatch python3 setup.py user add bob --role admin --email bob@example.com --no-password` |
| Change a password | `sudo -u logwatch python3 setup.py user passwd alice` |
| Change the role | `sudo -u logwatch python3 setup.py user role alice admin` |
| Set the e-mail used for SSO | `sudo -u logwatch python3 setup.py user email alice alice@example.com` |
| Rename | `sudo -u logwatch python3 setup.py user rename alice alice.smith` |
| Disable, enable or delete | `sudo -u logwatch python3 setup.py user disable alice` (`enable`, `delete`) |
| Reset MFA (lost phone) | `sudo -u logwatch python3 setup.py user mfa-reset alice` |
| Sign one user out everywhere | `sudo -u logwatch python3 setup.py user signout alice` |
| Require MFA for password sign-in | `sudo -u logwatch python3 setup.py user policy --mfa-required on` |
| Locked out: reset the admin | `sudo -u logwatch python3 setup.py set-password` (keeps the current admin name; `--user NAME` creates or resets that admin) |
| Sign everyone out | `sudo -u logwatch python3 setup.py secret SESSION_SECRET --generate`, then `sudo docker compose restart board` |
| All options | `sudo -u logwatch python3 setup.py user --help` |

Passwords need at least 12 characters (`board.min_password_length` in `config/config.yaml`, 4 to 128), and the commands read them from a prompt or from stdin, never from arguments.
For scripts, use `printf '%s\n' "$PW" | sudo -u logwatch python3 setup.py user passwd alice --stdin`. The board won't
demote, disable or delete the last admin.

**MFA**: in Settings → Account → Set up MFA, scan the QR code with any authenticator app (Google or Microsoft
Authenticator, 1Password, Bitwarden, Aegis…). You get 10 one-time recovery codes. With *Require MFA* on, users who
sign in with a password must set up MFA before they can do anything else. SSO sign-ins rely on the provider's own MFA.

### Single sign-on (Google, Microsoft, Discord, GitHub, OpenID Connect)

1. In **Users & sign-in → Board URL**, set how users open the board, e.g. `https://logwatch.example.com`. You can also
   run `setup.py user policy --url https://logwatch.example.com`.
2. Under **Single sign-on**, pick the type. The form shows the redirect URI, `https://logwatch.example.com/auth/sso/<id>/callback`,
   and a link to that provider's console.
3. Create an OAuth app there with that redirect URI, then paste its client ID and secret into the form.
   - **Google**: Cloud console → APIs & Services → Credentials → OAuth client ID (Web application).
   - **Microsoft**: Entra ID → App registrations. Set *Tenant* to your directory ID or domain. Multi-tenant
     (`common`) isn't allowed.
   - **Discord**: Developer Portal → your application → OAuth2. Discord e-mails count only when they're verified.
   - **GitHub**: Settings → Developer settings → OAuth Apps. The board uses the account's verified e-mails.
   - **OpenID Connect** (Authentik, Keycloak, Authelia, Zitadel…): the issuer URL, i.e. the part before
     `/.well-known/openid-configuration`.
4. A provider signs in a board user whose **e-mail** matches the verified e-mail it reports. Set that e-mail on each
   user, or turn on **auto-create** with a role and, ideally, your e-mail domains.

From the VM: `printf '%s\n' "$SECRET" | sudo -u logwatch python3 setup.py user sso add --kind google --client-id ID`,
plus `sso list`, `sso off ID` and `sso remove ID`.

Who can reach the login is set in `config/config.yaml` under `board:`: `allow_cidrs` (only these networks),
`open_cidrs` (these skip the login and get `open_role`), `session_hours`, `min_password_length`, and `cf_access` for Cloudflare Access. An
Access user whose e-mail matches a board user gets that user's role; anyone else gets `cf_access.role`. Both roles
default to `admin`, so set them to `auditor` if those visitors should only look.

## Secrets and modules

| Task | Command |
|---|---|
| Store or replace an API key / token | `sudo -u logwatch python3 setup.py secret PROXMOX_TOKEN` (prompts, never printed) |
| Generate a random token | `sudo -u logwatch python3 setup.py secret INGEST_TOKEN --generate` |
| List modules | `sudo -u logwatch python3 setup.py modules` |
| Turn modules on / off | `sudo -u logwatch python3 setup.py modules --enable uptime,expiry --disable netflow` |
| Check config and required secrets | `sudo -u logwatch python3 setup.py check` |
| Apply config changes | `sudo -u logwatch python3 setup.py render && sudo docker compose up -d --build && sudo docker compose restart board worker` |
| The board's SSH public key | `sudo -u logwatch python3 setup.py pubkey` |
| Env file for the AI runner | `sudo -u logwatch python3 setup.py runner-env --out runner.env --url https://logwatch.example.com` |

After editing `config/config.yaml` by hand, run the *Apply config changes* line. You can also turn on new features from
the board: **Features** in the sidebar, and change settings there with **Edit settings** (the installer in edit
mode, started by the host helper; it closes after Save & restart or 30 minutes: `journalctl -u logwatch-installer`).
`sudo .venv/bin/python -m installer pending` refreshes the setup list the board shows (the host helper does this itself).

## Service

| Task | Command |
|---|---|
| Status | `sudo docker compose ps` |
| Follow the logs | `sudo docker compose logs -f board worker` |
| Restart | `sudo docker compose restart board worker` |
| Stop / start | `sudo docker compose stop` / `sudo docker compose up -d` |
| Update to a version now | `sudo ./update.sh --version 2.2.1` |
| Update logs | `/var/log/logwatch-update-<version>.log` |
| Backups made before each update | `/var/backups/logwatch-dashboard` (last 3) |

