"""Log explorer details: everything the board can tell about one log line (Logs tab → click a line).

facts(x)   type-specific fields, parsed out of the message where the shipper didn't split them
users(x)   usernames in the line, with the outcome (ok / failed / seen) and how they were used
detail(x)  facts + users + the SSH session the line belongs to + the source IP across all logs (±24 h):
           every username tried from it, which hosts/apps saw it, what it requested
"""
import datetime as dt
import ipaddress
import json
import re
from collections import Counter

from common import iso, vl, vl_ts
from geo import geo

WIN_EVENTS = {
    "4624": "Logon succeeded", "4625": "Logon failed", "4634": "Logoff", "4647": "User-initiated logoff", "4648": "Logon with explicit credentials",
    "4672": "Admin privileges assigned to new logon", "4720": "User account created", "4722": "User account enabled", "4723": "Password change attempt",
    "4724": "Password reset attempt", "4725": "User account disabled", "4726": "User account deleted", "4728": "Member added to a security group",
    "4729": "Member removed from a security group", "4732": "Member added to a local group", "4733": "Member removed from a local group",
    "4738": "User account changed", "4740": "Account locked out", "4756": "Member added to a universal group", "4767": "Account unlocked",
    "4768": "Kerberos TGT requested", "4769": "Kerberos service ticket requested", "4771": "Kerberos pre-authentication failed",
    "4776": "NTLM credential validation", "4778": "Remote session reconnected", "4779": "Remote session disconnected",
    "4800": "Workstation locked", "4801": "Workstation unlocked", "1102": "Security log cleared", "7045": "Service installed",
    "5807": "Clients from IPs without an AD site", "10016": "DCOM permission denied",
}
WIN_FAIL = {"4625", "4771", "4776", "4740"}
WIN_OK = {"4624", "4648", "4768", "4769", "4778"}
LOGON_TYPES = {"2": "interactive (console)", "3": "network (SMB, NTLM, shares)", "4": "batch / scheduled task", "5": "service", "7": "unlock",
               "8": "network cleartext", "9": "new credentials (runas /netonly)", "10": "remote interactive (RDP)", "11": "cached interactive"}
NT_STATUS = {"0xc000006d": "bad username or password", "0xc000006a": "wrong password", "0xc0000064": "user does not exist",
             "0xc000006e": "account restriction", "0xc000006f": "outside allowed logon hours", "0xc0000070": "workstation not allowed",
             "0xc0000071": "password expired", "0xc0000072": "account disabled", "0xc0000193": "account expired", "0xc0000224": "must change password",
             "0xc0000234": "account locked out", "0xc000015b": "logon type not granted", "0x18": "wrong password (Kerberos)",
             "0x6": "user does not exist (Kerberos)", "0x12": "account disabled/locked (Kerberos)", "0x17": "password expired (Kerberos)"}
HTTP = {200: "OK", 201: "created", 204: "no content", 301: "moved permanently", 302: "redirect", 304: "not modified", 400: "bad request",
        401: "not signed in", 403: "forbidden", 404: "not found", 405: "method not allowed", 408: "client timed out", 413: "request too large",
        429: "rate-limited", 444: "closed without response", 499: "client closed the connection", 500: "server error", 502: "bad gateway",
        503: "service unavailable", 504: "upstream timed out"}
SEVERITY = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
PORTS = {"21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP", "110": "POP3", "123": "NTP", "143": "IMAP", "443": "HTTPS",
         "445": "SMB", "465": "SMTPS", "587": "SMTP submission", "993": "IMAPS", "995": "POP3S", "1433": "MSSQL", "3306": "MySQL", "3389": "RDP",
         "5432": "PostgreSQL", "5900": "VNC", "6379": "Redis", "8006": "Proxmox", "8080": "HTTP alt", "8443": "HTTPS alt", "25565": "Minecraft",
         "27015": "Source engine", "28015": "Rust"}
NET = ("traffic", "unifi_flow", "netflow", "dns")

U = r"([^\s'\"<>()\[\],;]{1,64})"   # a username token
# (regex, outcome, how): first group that matches = the user; outcome ok | fail | seen
PATTERNS = [
    (re.compile(r"\bAccepted (\S+) for " + U + r" from"), "ok", "SSH {0}"),
    (re.compile(r"\bFailed (\S+) for invalid user " + U + r" from"), "fail", "SSH {0} (user doesn't exist)"),
    (re.compile(r"\bFailed (\S+) for " + U + r" from"), "fail", "SSH {0}"),
    (re.compile(r"\bInvalid user " + U + r" from"), "fail", "SSH (user doesn't exist)"),
    (re.compile(r"\b(?:Connection closed|Connection reset|Disconnected) (?:by|from) invalid user " + U + r" "), "fail", "SSH (user doesn't exist)"),
    (re.compile(r"\b(?:Connection closed|Connection reset|Disconnected) (?:by|from) authenticating user " + U + r" "), "fail", "SSH (gave up while authenticating)"),
    (re.compile(r"\bmaximum authentication attempts exceeded for (?:invalid user )?" + U + r" from"), "fail", "SSH (too many attempts)"),
    (re.compile(r"\bDisconnected from user " + U + r" "), "seen", "SSH session ended"),
    (re.compile(r"\bsession opened for user " + U + r"(?:\(uid=\d+\))?(?: by (\S+))?"), "ok", "session opened"),
    (re.compile(r"\bsession closed for user " + U), "seen", "session closed"),
    (re.compile(r"\bAccepted key \S+ \S+ found at /(?:home/([^/\s]+)|(root))/"), "ok", "SSH key"),
    (re.compile(r"\bsuccessful auth for user '" + U + "'"), "ok", "Proxmox login"),
    (re.compile(r"\bauthentication failure; rhost=\S* user=" + U + r" msg="), "fail", "Proxmox login"),
    (re.compile(r"\bauthentication failure;.*?\buser=" + U), "fail", "PAM login"),
    (re.compile(r"\bpam_unix\([^)]*\): check pass; user unknown"), "fail", "PAM (unknown user)"),
    (re.compile(r"\bFAILED (?:LOGIN|su) .*?\b(?:FOR|for) '?" + U), "fail", "login"),
    (re.compile(r"\bUser \"" + U + r"\" successfully authenticated"), "ok", "Guacamole login"),
    (re.compile(r"\bAuthentication attempt from \S+ for user \"" + U + r"\" failed"), "fail", "Guacamole login"),
    (re.compile(r"\bsasl_username=" + U), "ok", "mail (SASL)"),
    (re.compile(r"\bSASL \S+ authentication failed.*?(?:sasl_username=" + U + ")?"), "fail", "mail (SASL)"),
    (re.compile(r"\bauth failed.*?\buser=<" + U + ">"), "fail", "mail (IMAP/POP3)"),
    (re.compile(r"\bLogin: user=<" + U + ">"), "ok", "mail (IMAP/POP3)"),
    (re.compile(r"\bnew user: name=" + U), "seen", "user account created"),
    (re.compile(r"\bdelete user '" + U + "'"), "seen", "user account deleted"),
    (re.compile(r"\bpassword changed for " + U), "seen", "password changed"),
    (re.compile(r"\bNew session \S+ of user " + U), "ok", "login session"),
]
GENERIC = re.compile(r"\b(?:user(?:name)?|login|account|uid)[=:]\s?['\"<]?([A-Za-z0-9_.@$\\-]{1,64})", re.I)
NOT_USERS = {"", "-", "unknown", "null", "none", "(unknown)", "n/a", "0"}


def _ip(s):
    try:
        return str(ipaddress.ip_address(str(s).strip("[]")))
    except ValueError:
        return ""


def _msg(x):
    return str(x.get("_msg") or "")


def _app(x):
    return str(x.get("app_name") or "")


def src_ip(x):
    """Where the connection came from, if the line has one."""
    for k in ("src", "src_ip", "client", "rhost", "ip"):
        if _ip(x.get(k, "")):
            return _ip(x[k])
    m = _msg(x)
    for r in (r"Source Network Address:\s*([0-9a-fA-F.:]{3,45})", r"Client Address:\s*(?:::ffff:)?([0-9a-fA-F.:]{3,45})",
              r"\bfrom (?:invalid user \S+ |authenticating user \S+ |user \S+ )?\[?([0-9a-fA-F.:]{3,45})\]?(?: port|\s|$)",
              r"\b([0-9a-fA-F]{1,4}[.:][0-9a-fA-F.:]{2,44}) port \d+", r"\brhost=([0-9a-fA-F.:]{3,45})", r"\bSRC=([0-9a-fA-F.:]{3,45})", r"\bclient(?: address)?[=: ]\[?([0-9a-fA-F.:]{3,45})"):
        k = re.search(r, m)
        if k and _ip(k.group(1)) and _ip(k.group(1)) not in ("127.0.0.1", "::1"):
            return _ip(k.group(1))
    if _app(x) == "crowdsec-event":
        try:
            return _ip(json.loads(m).get("ip", ""))
        except ValueError:
            pass
    return ""


def _win_kv(m):
    """Windows event text "Section:\\n\\tKey:\\t\\tValue" → [(section, key, value)]."""
    out, sec = [], ""
    for line in m.replace("\r", "").split("\n"):
        if not line.strip():
            continue
        k = re.match(r"^(\t*)([^\t:][^:]{0,60}):\t*(.*)$", line)
        if not k:
            continue
        ind, key, val = k.groups()
        if not ind and not val.strip():
            sec = key.strip()
        elif val.strip():
            v = val.strip()
            out.append((sec if ind else "", key.strip(), v[1:-1] if len(v) > 1 and v[0] == v[-1] == '"' else v))
    return out


def users(x):
    """[{user, outcome, how}] for every username in the line."""
    m, out, t = _msg(x), [], x.get("type")

    def add(u, outcome, how):
        u = str(u or "").strip().strip("'\"<>")
        if u.lower() in NOT_USERS or u.endswith("$") and how.startswith("Windows") and outcome == "seen" or _ip(u):
            return
        if not any(o["user"] == u and o["how"] == how for o in out):
            out.append({"user": u, "outcome": outcome, "how": how})
    if t == "winevt":
        eid = str(x.get("EventID") or "")
        how = "Windows " + WIN_EVENTS.get(eid, f"event {eid}").lower()
        oc = "fail" if eid in WIN_FAIL else "ok" if eid in WIN_OK else "seen"
        kv = _win_kv(m)
        targ = [v for s, k, v in kv if k == "Account Name" and s in ("New Logon", "Account For Which Logon Failed", "Account Information",
                                                                     "Target Account", "Member", "Account Whose Credentials Were Used", "")]
        for u in [x.get("TargetUserName")] + targ:
            if u:
                add(u, oc, how)
        for s, k, v in kv:
            if k in ("Logon Account", "Account Name") and s in ("", "Subject") and v not in targ:
                add(v, "seen", how + " (by)")
        if x.get("UserID") and "\\" in str(x["UserID"]):
            add(str(x["UserID"]), "seen", "Windows (process user)")
        return out
    if t in ("traffic",):
        for k in ("remote_user", "user"):
            if x.get(k) and x[k] != "-":
                add(x[k], "ok" if str(x.get("status", "")).startswith(("2", "3")) else "fail", "HTTP auth")
        return out
    if _app(x) == "sudo":
        k = re.match(r"\s*(\S+) : (?:.*?; )?(?:TTY=\S+ ; )?PWD=\S+ ; USER=(\S+) ; COMMAND=", m)
        if k:
            add(k.group(1), "ok", "sudo (ran as " + k.group(2) + ")")
            return out
        k = re.match(r"\s*(\S+) : .*(incorrect password attempts|NOT in sudoers|command not allowed)", m)
        if k:
            add(k.group(1), "fail", "sudo (" + k.group(2) + ")")
            return out
    if _app(x).upper() == "CRON":
        k = re.match(r"\s*\((\S+)\) CMD ", m)
        if k:
            add(k.group(1), "seen", "cron job")
            return out
    for rx, oc, how in PATTERNS:
        k = rx.search(m)
        if not k:
            continue
        g = [v for v in k.groups() if v]
        if how.startswith("SSH {0}"):
            add(g[1] if len(g) > 1 else g[0], oc, how.format(g[0]))
        else:
            add(g[0] if g else "", oc, how)
    if not out:
        for k in GENERIC.finditer(m):
            add(k.group(1), "fail" if re.search(r"\b(fail|invalid|denied|incorrect|bad)", m, re.I) else "seen", "mentioned in the line")
    if _app(x) == "crowdsec-event":
        try:
            meta = json.loads(m).get("meta") or {}
            for f in ("user", "username", "login"):
                if meta.get(f):
                    add(meta[f], "fail", "CrowdSec event")
        except ValueError:
            pass
    return out


def _f(k, v, field=None, hint=None):
    return {"k": k, "v": str(v), **({"f": field} if field else {}), **({"h": hint} if hint else {})}


def _port(p):
    return PORTS.get(str(p), "")


def facts(x):
    """Labelled facts for this line: the shipper's fields plus what's parsed out of the message."""
    t, m, app, out = x.get("type") or "", _msg(x), _app(x), []
    add = out.append
    try:
        ts = dt.datetime.fromisoformat(str(x["_time"]).replace("Z", "+00:00"))
        add(_f("Time (UTC)", ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]))
    except (KeyError, ValueError):
        pass
    host = x.get("hostname") or x.get("host") or x.get("node")
    if host:
        add(_f("Logged by", host, "hostname" if x.get("hostname") else "node" if x.get("node") else "host"))
    if t == "traffic" and x.get("proto") == "http":
        st = int(x["status"]) if str(x.get("status", "")).isdigit() else None
        add(_f("Request", f"{x.get('method', '')} {x.get('target', '')}{x.get('path', '')}"))
        for k, lbl in (("method", "Method"), ("target", "Site"), ("path", "Path")):
            if x.get(k):
                add(_f(lbl, x[k], k))
        if "?" in str(x.get("path", "")):
            add(_f("Query string", str(x["path"]).split("?", 1)[1]))
        if st is not None:
            add(_f("Status", f"{st} {HTTP.get(st, '')}".strip(), "status"))
        if x.get("upstream") and x.get("upstream") != x.get("status"):
            add(_f("Upstream status", x["upstream"], "upstream", "what the backend answered (- = never reached it)"))
        if x.get("bytes"):
            add(_f("Response size", f"{int(x['bytes']):,} B" if str(x["bytes"]).isdigit() else x["bytes"]))
        for k, lbl in (("ua", "User agent"), ("ref", "Referrer"), ("rt", "Response time")):
            if x.get(k) and x[k] != "-":
                add(_f(lbl, x[k], k))
    elif t == "traffic":
        add(_f("Protocol", str(x.get("proto", "")).upper(), "proto"))
        if x.get("dport"):
            add(_f("Destination port", f"{x['dport']} {_port(x['dport'])}".strip(), "dport"))
        if x.get("target"):
            add(_f("Target", x["target"], "target"))
        if x.get("bytes"):
            add(_f("Packet size", f"{x['bytes']} B", hint="IP length of the first packet"))
    if t == "traffic":
        if x.get("action"):
            add(_f("Edge action", x["action"], "action", "allowed, blocked by the WAF/CrowdSec, or dropped by the port-proxy rules"))
        if x.get("rule"):
            add(_f("Rule", x["rule"], "rule"))
    elif t == "unifi_flow":
        for k, lbl in (("action", "Action"), ("proto", "Protocol"), ("service", "Service"), ("src_name", "Source"), ("src_net", "Source network"),
                       ("dst_name", "Destination"), ("dst_net", "Destination network"), ("policy", "Policy"), ("risk", "Risk"),
                       ("ips_signature", "IPS signature"), ("ips_category", "IPS category")):
            if x.get(k):
                add(_f(lbl, x[k], k))
        if x.get("src_ip"):
            add(_f("From", f"{x['src_ip']}:{x.get('src_port', '')}", "src_ip"))
        if x.get("dst_ip"):
            add(_f("To", f"{x['dst_ip']}:{x.get('dst_port', '')} {_port(x.get('dst_port'))}".strip(), "dst_ip"))
    elif t == "dns":
        add(_f("Query", m.strip()))
        for k, lbl in (("qtype", "Record type"), ("client", "Client"), ("rcode", "Answer code"), ("answer", "Answer")):
            if x.get(k):
                add(_f(lbl, x[k], k))
    elif t == "unifi_event":
        for k, lbl in (("title", "Event"), ("category", "Category"), ("severity", "Severity"), ("key", "Event key")):
            if x.get(k):
                add(_f(lbl, x[k], k))
    elif t == "winevt":
        eid = str(x.get("EventID") or "")
        add(_f("Event", f"{eid} · {WIN_EVENTS.get(eid, x.get('ProviderName', ''))}", "EventID"))
        for k, lbl in (("Channel", "Channel"), ("ProviderName", "Provider"), ("Computer", "Computer")):
            if x.get(k):
                add(_f(lbl, x[k], k))
        lv = {"0": "audit", "1": "critical", "2": "error", "3": "warning", "4": "information", "5": "verbose"}.get(str(x.get("Level", "")))
        if lv:
            add(_f("Level", lv, "Level"))
        seen = set()
        for s, k, v in _win_kv(m):
            lbl = f"{s} · {k}" if s and k in ("Security ID", "Account Name", "Account Domain", "Logon ID") else k
            if lbl in seen or v in ("-", "0x0", "NULL SID") or len(v) > 300:
                continue
            seen.add(lbl)
            if k == "Logon Type":
                v = f"{v} · {LOGON_TYPES.get(v, '')}".strip(" ·")
            elif k in ("Status", "Sub Status", "Failure Code", "Error Code", "Result Code"):
                v = f"{v} · {NT_STATUS.get(v.lower(), '')}".strip(" ·")
            add(_f(lbl, v))
        if x.get("LogonType") and "Logon Type" not in seen:
            add(_f("Logon type", f"{x['LogonType']} · {LOGON_TYPES.get(str(x['LogonType']), '')}".strip(" ·"), "LogonType"))
    else:
        if app:
            add(_f("Program", app + (f" [{x['proc_id']}]" if x.get("proc_id") not in (None, "", "-") else ""), "app_name"))
        if x.get("unit"):
            add(_f("Systemd unit", x["unit"], "unit"))
        sv = str(x.get("severity", ""))
        if sv.isdigit() and int(sv) < 8:
            add(_f("Severity", f"{sv} · {SEVERITY[int(sv)]}", "severity"))
        elif x.get("level"):
            add(_f("Level", x["level"], "level"))
        if x.get("facility_keyword"):
            add(_f("Facility", x["facility_keyword"], "facility_keyword"))
        if app == "sudo":
            k = re.match(r"\s*(\S+) : (.*)$", m)
            if k:
                add(_f("Sudo by", k.group(1)))
                for kv in k.group(2).split(" ; "):
                    if "=" in kv:
                        a, b = kv.split("=", 1)
                        add(_f({"PWD": "Working directory", "USER": "Ran as", "COMMAND": "Command", "TTY": "Terminal"}.get(a.strip(), a.strip()), b.strip()))
        elif app.upper() == "CRON":
            k = re.match(r"\s*\((\S+)\) CMD \((.*)\)\s*$", m)
            if k:
                add(_f("Cron user", k.group(1)))
                add(_f("Command", k.group(2)))
        elif app == "crowdsec-event":
            try:
                j = json.loads(m)
                for k, lbl in (("scenario", "Scenario"), ("ip", "IP"), ("cn", "Country"), ("as", "Network (AS)"), ("decision", "Decision"),
                               ("duration", "Duration"), ("events", "Events"), ("simulated", "Simulated"), ("remediation", "Blocked")):
                    if j.get(k) not in (None, ""):
                        add(_f(lbl, ("yes" if j[k] else "no") if isinstance(j[k], bool) else j[k]))
                for k, v in (j.get("meta") or {}).items():
                    if v not in (None, ""):
                        add(_f(k.replace("_", " ").capitalize(), v))
            except ValueError:
                pass
        if re.search(r"\bIN=\S* OUT=", m):   # kernel / UFW firewall line
            kv = dict(re.findall(r"\b([A-Z]{2,6})=(\S*)", m))
            for k, lbl in (("IN", "In interface"), ("OUT", "Out interface"), ("SRC", "Source"), ("DST", "Destination"), ("PROTO", "Protocol"),
                           ("SPT", "Source port"), ("DPT", "Destination port"), ("LEN", "Length"), ("TTL", "TTL")):
                if kv.get(k):
                    add(_f(lbl, kv[k] + (f" {_port(kv[k])}" if k == "DPT" and _port(kv[k]) else "")))
            k = re.search(r"\[UFW (\w+)\]", m)
            if k:
                add(_f("UFW action", k.group(1)))
        k = re.search(r"\bport (\d{1,5})\b", m)
        if k and app.startswith("sshd"):
            add(_f("Source port", k.group(1)))
        k = re.search(r"\bssh2: (\S+) (SHA256:\S+)", m) or re.search(r"\bAccepted key (\S+) (SHA256:\S+)", m)
        if k:
            add(_f("SSH key", f"{k.group(1)} {k.group(2)}"))
        k = re.search(r"found at (\S+?):(\d+)$", m.strip())
        if k:
            add(_f("Key file", f"{k.group(1)} line {k.group(2)}"))
        if not any(o["k"] in ("Command", "Sudo by") for o in out):
            for a, b in re.findall(r"\b([A-Za-z_][\w.-]{1,30})=(\"[^\"]{0,200}\"|[^\s,;]{1,200})", m)[:20]:
                if a.isupper() and re.search(r"\bIN=\S* OUT=", m):
                    continue
                add(_f(a, b.strip('"')))
    ip = src_ip(x)
    if ip:
        cn, asn = (x.get("cn"), x.get("as")) if x.get("cn") else geo(ip)
        add(_f("Source IP", ip, "src" if x.get("src") else None))
        add(_f("Country", cn, "cn" if x.get("cn") else None))
        add(_f("Network (AS)", asn, "as" if x.get("as") else None))
    return out


def _q(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ip_query(ip):
    q = _q(ip)
    return f"({q} or src:={q} or src_ip:={q} or dst_ip:={q} or client:={q}) -type:netflow"


def _session(x, t):
    """Lines of the same sshd connection (same host + sshd process id), ±1 h."""
    if not _app(x).startswith("sshd") or x.get("proc_id") in (None, "", "-") or not x.get("hostname"):
        return []
    try:
        rows = vl(f"hostname:={_q(x['hostname'])} app_name:({_q(_app(x))}) proc_id:={_q(x['proc_id'])} | sort by (_time) | limit 200",
                  iso(t - 3600), iso(t + 3600), 200)
    except Exception:
        return []
    return rows


def _summ(us):
    """Merge per-line user hits into {user, ok, fail, seen, how:[...], hosts:[...], first, last}."""
    agg = {}
    for u, oc, how, host, ts in us:
        a = agg.setdefault(u, {"user": u, "ok": 0, "fail": 0, "seen": 0, "how": [], "hosts": [], "first": ts, "last": ts})
        a[oc] += 1
        if how not in a["how"]:
            a["how"].append(how)
        if host and host not in a["hosts"]:
            a["hosts"].append(host)
        a["first"], a["last"] = min(a["first"], ts), max(a["last"], ts)
    return sorted(agg.values(), key=lambda a: (-a["ok"] - a["fail"] - a["seen"], a["user"]))[:60]


def detail(x):
    t = vl_ts(x)
    out = {"facts": facts(x), "users": users(x), "session": None, "ip": None}
    sess = _session(x, t)
    if len(sess) > 1:
        hits = [(u["user"], u["outcome"], u["how"], r.get("hostname", ""), vl_ts(r)) for r in sess for u in users(r)]
        ips = [src_ip(r) for r in sess if src_ip(r)]
        out["session"] = {"lines": len(sess), "start": sess[0].get("_time"), "end": sess[-1].get("_time"), "ip": ips[0] if ips else "",
                          "users": _summ(hits), "pid": x.get("proc_id"), "host": x.get("hostname"),
                          "events": [r.get("_msg", "").strip()[:200] for r in sess][:40]}
    ip = src_ip(x) or (out["session"] or {}).get("ip") or ""
    if not ip:
        return out
    cn, asn = (x["cn"], x.get("as") or "?") if x.get("cn") and ip == _ip(x.get("src", "")) else geo(ip)
    info = {"ip": ip, "cn": cn, "asn": asn, "window": [iso(t - 86400), iso(t + 86400)]}
    q, s, e = _ip_query(ip), iso(t - 86400), iso(t + 86400)
    try:
        stats = vl(f"{q} | stats by (type, app_name, hostname, node) count() c | sort by (c desc) | limit 40", s, e, 40)
        info["seen"] = [{"type": r.get("type") or "", "app": r.get("app_name") or "", "host": r.get("hostname") or r.get("node") or "",
                         "n": int(r.get("c") or 0)} for r in stats]
        info["lines"] = sum(r["n"] for r in info["seen"])
        auth = vl(f"{q} -type:(traffic or unifi_flow or dns) (i(user) or i(accepted) or i(failed) or i(logon) or i(login) or i(authentication) or i(password) or i(account)) | sort by (_time desc) | limit 3000", s, e, 3000)
        info["capped"] = len(auth) >= 3000
        auth = [r for r in auth if src_ip(r) == ip]   # the IP is the connection's source, not just mentioned (sudo cscli … <ip>)
        hits = [(u["user"], u["outcome"], u["how"], r.get("hostname", ""), vl_ts(r)) for r in auth for u in users(r)]
        # sshd lines with the IP name the process; its other lines (key logins, session opened) name the user
        pids = list(dict.fromkeys((r.get("hostname"), r.get("app_name"), r.get("proc_id")) for r in auth
                                  if str(r.get("app_name", "")).startswith("sshd") and r.get("proc_id") not in (None, "", "-")))[:25]
        if pids:
            cond = " or ".join(f"(hostname:={_q(h)} app_name:={_q(a)} proc_id:={_q(p)})" for h, a, p in pids)
            seen = {(r.get("_time"), r.get("_msg")) for r in auth}
            more = [r for r in vl(f"({cond}) | limit 3000", s, e, 3000) if (r.get("_time"), r.get("_msg")) not in seen]
            hits += [(u["user"], u["outcome"], u["how"] + " · same SSH connection", r.get("hostname", ""), vl_ts(r)) for r in more for u in users(r)]
        info["users"] = _summ(hits)
        web = vl(f"{q} type:traffic proto:http | stats by (target, status, action) count() c | sort by (c desc) | limit 12", s, e, 12)
        info["web"] = [{"target": r.get("target") or "", "status": r.get("status") or "", "action": r.get("action") or "", "n": int(r.get("c") or 0)} for r in web]
        net = vl(f"{q} type:traffic -proto:http | stats by (node, proto, action) count() c, count_uniq(dport) ports | sort by (c desc) | limit 8", s, e, 8)
        info["conns"] = [{"node": r.get("node") or "", "proto": r.get("proto") or "", "action": r.get("action") or "", "n": int(r.get("c") or 0),
                          "ports": int(r.get("ports") or 0)} for r in net]
        top = vl(f"{q} type:traffic -proto:http | stats by (dport) count() c | sort by (c desc) | limit 10", s, e, 10)
        info["dports"] = [{"port": r.get("dport") or "", "name": _port(r.get("dport")), "n": int(r.get("c") or 0)} for r in top if r.get("dport")]
        paths = vl(f"{q} type:traffic proto:http | stats by (method, path) count() c | sort by (c desc) | limit 12", s, e, 12)
        info["paths"] = [{"method": r.get("method") or "", "path": r.get("path") or "", "n": int(r.get("c") or 0)} for r in paths]
        span = vl(f"{q} | stats min(_time) first, max(_time) last", s, e, 1)
        if span:
            info["first"], info["last"] = span[0].get("first"), span[0].get("last")
    except Exception as ex:
        info["error"] = str(ex)[:200]
    out["ip"] = info
    return out


if __name__ == "__main__":   # quick self-check of the parsers
    for line in [" Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2",
                 " Accepted publickey for alice from 192.0.2.66 port 35618 ssh2: ED25519 SHA256:abc",
                 " Connection closed by authenticating user root 5.6.7.8 port 4242 [preauth]",
                 " pam_unix(sshd:session): session opened for user alice(uid=1000) by alice(uid=0)",
                 " Accepted key ED25519 SHA256:xyz found at /home/alice/.ssh/authorized_keys:1",
                 " <root@pam> successful auth for user 'root@pam'",
                 " alice : PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/true"]:
        x = {"_msg": line, "app_name": "sudo" if "PWD=" in line else "pvedaemon" if "pam>" in line else "sshd-session", "hostname": "h"}
        print(users(x), src_ip(x))
