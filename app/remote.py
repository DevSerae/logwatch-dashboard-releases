"""SSH to monitored hosts. Every host runs the same forced command (/usr/local/sbin/logwatch-remote, see remote/linux),
so the key can only run the roles that host's /etc/logwatch-remote.conf enables: logpull, trafficpull, csctl, images,
waf."""
import json
import subprocess

from settings import DATA, SSH_KEY, section, ssh_host

KNOWN = DATA / "ssh" / "known_hosts"


def run(name, command, timeout=90, stdin=None):
    """Run '<role> <args>' on a configured host (stdin: text fed to it). Returns CompletedProcess (text)."""
    h = ssh_host(name)
    if not h:
        raise RuntimeError(f"host {name!r} is not in ssh.hosts")
    KNOWN.parent.mkdir(parents=True, exist_ok=True)
    user = h.get("user") or section("ssh").get("user") or "logwatch"
    cmd = ["ssh", "-i", str(SSH_KEY), "-p", str(h.get("port") or 22), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
           "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={KNOWN}",
           "-o", "LogLevel=ERROR", "-l", user, "--", h.get("address") or name, command]
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout,
                          stdin=None if stdin is not None else subprocess.DEVNULL)


def json_lines(name, command, timeout=90):
    """Run a streaming role (logpull/trafficpull): JSON lines ending with {"k": "end", ...}."""
    out = run(name, command, timeout)
    lines = []
    for x in out.stdout.splitlines():
        if x.strip():
            try:
                lines.append(json.loads(x))
            except ValueError:
                pass
    if not lines or lines[-1].get("k") != "end":
        raise RuntimeError((out.stderr.strip() or f"no output (exit {out.returncode})")[-300:])
    return lines
