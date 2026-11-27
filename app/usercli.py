"""Board users from the command line (runs inside the board container; on the host use `python3 setup.py user ...`).

  list                                     users, roles, MFA, last sign-in
  add NAME [--role admin|auditor] [--email E] [--password-stdin]
  passwd NAME [--create-admin]             new password from stdin (--create-admin: add NAME as admin if missing)
  role NAME admin|auditor
  email NAME E                             '' removes it (SSO sign-in stops matching)
  rename OLD NEW
  disable NAME | enable NAME | delete NAME
  mfa-reset NAME                           turn off MFA (lost phone); they set it up again at next sign-in
  signout NAME                             sign NAME out everywhere
  policy [--mfa-required on|off] [--url https://board.example.com]
  sso list | sso on ID | sso off ID | sso remove ID
  sso add --kind google|microsoft|discord|github|oidc --client-id X [--id ID] [--label L] [--issuer URL|TENANT]
          [--auto-role admin|auditor] [--domains a.com,b.com] [--trust-email]   (client secret from stdin)

Changes apply at once: no restart needed. Passwords and client secrets are read from stdin, never from arguments."""
import argparse
import sys
import time

import db
import sso
import users


def out(*a):
    print(*a, flush=True)


def stdin_line(what):
    v = sys.stdin.readline().rstrip("\n")
    if not v:
        raise users.UserError(f"no {what} on stdin")
    return v


def when(ts):
    if not ts:
        return "never"
    s = time.time() - ts
    return f"{int(s // 60)}m ago" if s < 3600 else f"{int(s // 3600)}h ago" if s < 86400 else f"{int(s // 86400)}d ago"


def cmd_list(con, a):
    rows = users.all_users(con)
    if not rows:
        out("no users yet: python3 setup.py set-password")
    w = max([len(r["name"]) for r in rows] + [4])
    for r in rows:
        mfa = f"MFA ({r['recovery_left']} recovery)" if r["totp_on"] else "no MFA"
        how = "+".join(x for x, on in (("password", r["has_pw"]), ("SSO", r["email"])) if on)
        out(f"{r['name']:<{w}}  {r['role']:<7}  {'DISABLED ' if r['disabled'] else ''}{how:<12}  {mfa:<20}  "
            f"{r['email'] or '-':<28}  last sign-in {when(r['last_login'])}{' via ' + r['last_via'] if r['last_via'] else ''}")


def cmd_sso(con, a):
    if a.op == "list":
        ps = sso.providers(con)
        if not ps:
            out("no SSO providers (add one: Users & sign-in on the board, or `sso add`)")
        base = users.policy(con)["public_url"] or "https://<board URL>"
        for p in ps:
            out(f"{p['id']:<12} {p['kind']:<10} {'on ' if p['enabled'] else 'off'}  "
                f"{'auto-create ' + p['auto_role'] + (' (' + p['domains'] + ')' if p['domains'] else '') if p['auto_role'] else 'existing users only':<36}"
                f"  redirect {sso.redirect_uri(base, p['id'])}")
        return
    if a.op == "add":
        f = {"kind": a.kind, "id": a.id or a.kind, "label": a.label, "client_id": a.client_id, "issuer": a.issuer,
             "auto_role": a.auto_role, "domains": a.domains, "trust_email": a.trust_email}
        f["client_secret"] = sys.stdin.readline().rstrip("\n")  # empty = keep the stored one
        p = sso.save(con, f)
        base = users.policy(con)["public_url"]
        out(f"saved {p['label']} ({p['id']}); redirect URI: {sso.redirect_uri(base or 'https://<board URL>', p['id'])}")
        if not base:
            out("set the board URL so redirects match: setup.py user policy --url https://logwatch.example.com")
        return
    if not a.target or not sso.get(con, a.target):
        raise sso.SSOError(f"no provider {a.target!r}")
    if a.op == "remove":
        con.execute("DELETE FROM sso_providers WHERE id=?", (a.target,))
    else:
        con.execute("UPDATE sso_providers SET enabled=? WHERE id=?", (1 if a.op == "on" else 0, a.target))
    out(f"{a.target}: {a.op}")


def run(con, a):
    c = a.cmd
    if c == "list":
        return cmd_list(con, a)
    if c == "sso":
        return cmd_sso(con, a)
    if c == "add":
        u = users.create(con, a.name, a.role, a.email or "", stdin_line("password") if a.password_stdin else "")
        return out(f"added {u['name']} ({u['role']})")
    if c == "passwd":
        pw = stdin_line("password")
        if not users.get(con, a.name):
            if not a.create_admin:
                raise users.UserError(f"no user {a.name} (add --create-admin to create it)")
            users.create(con, a.name, "admin", "", pw)
            return out(f"added {a.name} (admin)")
        users.set_password(con, a.name, pw)
        return out(f"password set for {a.name}; their sessions are signed out")
    if c == "role":
        users.update(con, a.name, role=a.role)
    elif c == "email":
        users.update(con, a.name, email=a.email)
    elif c == "rename":
        users.rename(con, a.name, a.new)
    elif c in ("disable", "enable"):
        users.update(con, a.name, disabled=c == "disable")
    elif c == "delete":
        users.delete(con, a.name)
    elif c in ("mfa-reset", "signout"):
        if not users.get(con, a.name):
            raise users.UserError(f"no user {a.name}")
        (users.reset_mfa if c == "mfa-reset" else users.sign_out_everywhere)(con, users.get(con, a.name)["name"])
    elif c == "policy":
        kw = {}
        if a.mfa_required:
            kw["mfa_required"] = a.mfa_required == "on"
        if a.url is not None:
            kw["public_url"] = a.url.strip().rstrip("/")
        p = users.set_policy(con, **kw)
        return out(f"MFA required for password sign-in: {'yes' if p['mfa_required'] else 'no'} · "
                   f"board URL: {p['public_url'] or '(from each request)'}")
    out("done")


def main():
    p = argparse.ArgumentParser(prog="setup.py user", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    s = p.add_subparsers(dest="cmd", required=True)
    s.add_parser("list")
    x = s.add_parser("add")
    x.add_argument("name")
    x.add_argument("--role", default="auditor", choices=users.ROLES)
    x.add_argument("--email")
    x.add_argument("--password-stdin", action="store_true")
    x = s.add_parser("passwd")
    x.add_argument("name")
    x.add_argument("--create-admin", action="store_true")
    x = s.add_parser("role")
    x.add_argument("name")
    x.add_argument("role", choices=users.ROLES)
    x = s.add_parser("email")
    x.add_argument("name")
    x.add_argument("email")
    x = s.add_parser("rename")
    x.add_argument("name")
    x.add_argument("new")
    for c in ("disable", "enable", "delete", "mfa-reset", "signout"):
        s.add_parser(c).add_argument("name")
    x = s.add_parser("policy")
    x.add_argument("--mfa-required", choices=("on", "off"))
    x.add_argument("--url")
    x = s.add_parser("sso")
    x.add_argument("op", choices=("list", "add", "on", "off", "remove"))
    x.add_argument("target", nargs="?")
    x.add_argument("--kind", choices=tuple(sso.PRESETS))
    x.add_argument("--id")
    x.add_argument("--label")
    x.add_argument("--client-id")
    x.add_argument("--issuer", default="")
    x.add_argument("--auto-role", default="", choices=("",) + users.ROLES)
    x.add_argument("--domains", default="")
    x.add_argument("--trust-email", action="store_true")
    a = p.parse_args()
    try:
        with db.connect() as con:
            users.ensure(con)
            sso.ensure(con)
            run(con, a)
            if a.cmd not in ("list",) and not (a.cmd == "sso" and a.op == "list"):
                db.add_event(con, "auth", f"setup.py user {a.cmd}{' ' + a.op if a.cmd == 'sso' else ''}"
                             f"{' ' + a.name if getattr(a, 'name', None) else ''}", "from the command line")
    except (users.UserError, sso.SSOError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
