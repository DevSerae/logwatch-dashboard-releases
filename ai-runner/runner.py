#!/usr/bin/env python3
"""Logwatch Dashboard "Resolve with AI" runner. Python 3.8+, standard library only.

Runs on whatever machine has your AI agent CLI (and its access to your network): a workstation, a container, a VM.
It polls the board over HTTP(S) with AI_RUNNER_TOKEN for queued runs, runs the agent headless with the incident as the
prompt, streams the transcript back while it works (shown live on the board's /ai/<id> page) and reports the outcome.
Only outbound connections: the board never connects to the runner.

Config (environment, or a KEY=VALUE file passed with --env; `python3 setup.py runner-env` on the board writes one):
  LOGWATCH_URL       board URL, e.g. https://logwatch.example.com              (required)
  AI_RUNNER_TOKEN    same value as in the board's secrets.env                  (required)
  AGENT              claude | codex | gemini | opencode | command              (default claude)
  AGENT_CMD          for AGENT=command: shell command; {prompt_file} is replaced, or the prompt arrives on stdin
  AGENT_BIN          path to the agent binary if it's not on PATH
  AGENT_EXTRA_ARGS   extra CLI args (model, permission mode...), split like a shell would; {run_id} is replaced
  AGENT_CWD          working directory for the agent (default: home). Put its own instructions/memory there.
  AGENT_NOTES        optional file with notes about your environment, appended to every prompt
  RUN_TIMEOUT        seconds per run (default 3600)
  POLL_SECONDS       default 10
  CA_BUNDLE          CA file if the board uses a private CA; INSECURE_TLS=1 skips verification (not recommended)
"""
import argparse
import fcntl
import json
import os
import queue
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

SECRET = re.compile(r"(?i)\b([\w.-]*(?:key|token|secret|passw(?:or)?d|pwd|auth)[\w.-]*\s*[=:]\s*)(\"?)[^\s\"']{6,}")
BEARER = re.compile(r"(?i)(bearer\s+)[\w.~+/=-]{8,}")


def log(*a):
    print(time.strftime("%F %T"), *a, flush=True)


def load_env(path):
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def trim(s, n):
    s = s if isinstance(s, str) else json.dumps(s)
    s = BEARER.sub(r"\1[redacted]", SECRET.sub(lambda m: m.group(1) + m.group(2) + "[redacted]", s))
    return s if len(s) <= n else s[:n] + f"\n… ({len(s) - n:,} more chars)"


# --- board API ----------------------------------------------------------------------------------------------------

class Board:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip("/"), token
        self.ctx = None
        if os.environ.get("INSECURE_TLS") == "1":
            self.ctx = ssl._create_unverified_context()
        elif os.environ.get("CA_BUNDLE"):
            self.ctx = ssl.create_default_context(cafile=os.environ["CA_BUNDLE"])

    def post(self, path, body=None, timeout=60):
        req = urllib.request.Request(self.url + path, data=json.dumps(body or {}).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
            return json.loads(r.read() or b"null")


# --- prompt -------------------------------------------------------------------------------------------------------

def ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "?"


def incident(job, head="## Incident", logn=40):
    it = job["item"]
    hist = "\n".join(f"- {ts(h['ts'])} {h['action']}" + (f" ({h['who']})" if h.get("who") else "") +
                     (f": {h['note']}" if h.get("note") else "") for h in job.get("hist", [])[-30:]) or "- none"
    logs = "\n".join(f"{ts(l.get('ts'))} {l.get('host', '')} {l.get('app', '')}: {l.get('msg', '')}"
                     for l in (job.get("logs") or [])[:logn]) or "(none found)"
    return f"""{head}
- key: {it['key']}
- source: {it['source']} · kind: {it['kind']} · severity: {it['severity']} · state: {it['state']}
- title: {it['title']}
- first seen {ts(it['first_seen'])} · last seen {ts(it['last_seen'])} · seen {it['count']}x
- operator's note: {it.get('note') or '(none)'}

Detail:
{it['detail'] or '(none)'}

Board history:
{hist}

Related log lines (the board's VictoriaLogs, query `{job.get('query') or '-'}`, newest first):
{logs}
"""


def notes():
    if os.environ.get("AGENT_NOTES") and Path(os.environ["AGENT_NOTES"]).exists():
        return "\n## Notes about this environment (from the operator)\n" + Path(os.environ["AGENT_NOTES"]).read_text()[:20000]
    return ""


def knowns(job):
    """Facts the operator recorded on the board (Knowns): true, and they win over what the logs seem to say."""
    ks = [k for k in job.get("knowns") or [] if isinstance(k, dict) and k.get("text")]
    if not ks:
        return ""
    return "\n## Knowns (facts from the operator; treat them as true)\n" + "\n".join(
        f"- {k['text']}" + (f" (covers board items matching `{k['match']}`)" if k.get("match") else "") for k in ks[:100]) + \
        "\nIf a known explains the incident (e.g. something is down on purpose), change nothing and say so.\n"


RULES = """## How to work
1. Use whatever you already know about this environment (your instructions, memory, notes above) before acting.
2. Find the root cause, apply the smallest safe fix, and verify it actually worked.
3. Don't do anything that needs the operator's approval: production changes or restarts they haven't pre-approved,
   anything destructive or hard to reverse, outward-facing changes, work beyond {scope}, or credentials you don't
   have. Stop instead and say exactly what is needed.
4. Don't resolve, mute or snooze {items} on the board; the operator checks your work and presses Resolve.
5. Never print secrets (tokens, passwords, keys) in your output.
{ask}"""

ASK_RULE = """6. If one concrete action you couldn't take under rule 3 would fix it, prepare everything that is safe (diagnose, back up,
   download) and then ask for it: answer `needs_approval` and put the exact action on the APPROVAL line, specific
   enough to run as written (host, path, command, what you back up first). The board shows it to the operator with
   Approve / Deny buttons; Approve starts a new run that is allowed to do exactly that. Ask for one action, not a menu.
"""


def ask_rule(job):
    return ASK_RULE if (job.get("board") or {}).get("approvals") else ""


def approved(job):
    """The action the operator approved on the board for this run (after an earlier run asked for it)."""
    a = (job.get("approved") or "").strip()
    return f"""
## Approved by the operator
An earlier run on this incident asked for approval and the operator approved exactly this action:
> {a}
Carry it out now, as written, then verify that it fixed the incident. This approval covers that action only:
anything beyond it still falls under rule 3.
""" if a else ""


def prompt(job):
    b = job.get("board") or {}
    return f"""You are resolving an incident from {b.get('title') or 'Logwatch Dashboard'}, a monitoring board for the operator's
network. {job.get('who') or 'The operator'} started this with the board's "Resolve with AI" button and can read your
transcript live on the board, but this is a headless run: you cannot ask questions and nobody will answer mid-run.

{incident(job)}{knowns(job)}{notes()}{approved(job)}
{RULES.format(scope="this incident", items="the item", ask=ask_rule(job))}
## End your final message with exactly this block (the board parses it):
OUTCOME: fixed   (or: {"not_fixed, or needs_approval" if ask_rule(job) else "not_fixed"})
{"APPROVAL: <only with needs_approval: the one action, on one line>" + chr(10) if ask_rule(job) else ""}SUMMARY:
Cause: <one or two sentences>
Changed: <what you changed, where; or "nothing" and why>
Verified: <how you checked; or what the operator must do>
"""


def group_prompt(job):
    b, runs = job.get("board") or {}, job["runs"]
    blocks = "\n".join(incident(r, f"## Incident {n}", 15) for n, r in enumerate(runs, 1))
    asks = ask_rule(job) or ask_rule(runs[0])
    ends = "\n\n".join(f"""OUTCOME {n}: fixed   (or: {"not_fixed, or needs_approval" if asks else "not_fixed"})
{f"APPROVAL {n}: <only with needs_approval: the one action for this incident, on one line>" + chr(10) if asks else ""}SUMMARY {n}:
Cause: <one or two sentences>
Changed: <what you changed, where; or "nothing" and why>
Verified: <how you checked; or what the operator must do>""" for n in range(1, len(runs) + 1))
    return f"""You are resolving {len(runs)} incidents from {b.get('title') or 'Logwatch Dashboard'}, a monitoring board for the
operator's network. {job.get('who') or 'The operator'} selected them together and started this with the board's "Resolve
with AI" button; they can read your transcript live on the board, but this is a headless run: you cannot ask questions
and nobody will answer mid-run.

Work on them together: incidents that share a cause (same host, same storage, same service) should be investigated and
fixed once, not {len(runs)} times. Then check each incident on its own.

{blocks}{knowns(job)}{notes()}
{RULES.format(scope="these incidents", items="the items", ask=asks)}
## End your final message with one block per incident, in this exact format (the board parses it and shows each block
## on its own incident; repeat a shared cause in each block it applies to):
{ends}
"""


OUTCOMES = r"(needs_approval|not_fixed|fixed)"


def parse_group(result, n):
    """Per-incident (outcome, summary, ask) from "OUTCOME <n>: … [APPROVAL <n>: …] SUMMARY <n>: …" blocks; whole tail
    when one is missing."""
    res, text = [], result or ""
    for k in range(1, n + 1):
        m = re.search(rf"OUTCOME {k}:\s*{OUTCOMES}(.*?)(?=OUTCOME \d+:|\Z)", text, re.S | re.I)
        if not m:
            res.append(("unknown", text[-1500:].strip(), ""))
            continue
        sm = re.search(rf"SUMMARY {k}:\s*(.+)", m.group(2), re.S | re.I)
        am = re.search(rf"APPROVAL {k}:[ \t]*(.+)", m.group(2), re.I)
        res.append((m.group(1).lower(), (sm.group(1) if sm else m.group(2)).strip(), am.group(1).strip() if am else ""))
    return res


def parse_outcome(result):
    m = re.search(rf"OUTCOME:\s*{OUTCOMES}", result or "", re.I)
    s = re.search(r"SUMMARY:\s*(.+)", result or "", re.S | re.I)
    a = re.search(r"APPROVAL:[ \t]*(.+)", result or "", re.I)
    summary = (s.group(1) if s else (result or "")[-1500:]).strip()
    return (m.group(1).lower() if m else "unknown"), summary, a.group(1).strip() if a else ""


# --- adapters: build the command and turn its stdout lines into board steps ---------------------------------------
# A step is {"t": "text", "text"} or {"t": "tool", "name", "desc", "input", "out", "err"}.

class Transcript:
    def __init__(self):
        self.steps, self.by_id, self.final = [], {}, ""

    def text(self, s):
        s = re.split(r"OUTCOME(?: \d+)?:", s or "")[0].strip()  # the closing block is shown as the summary already
        if s:
            self.steps.append({"t": "text", "text": trim(s, 4000)})

    def tool(self, tid, name, inp, desc=""):
        if isinstance(inp, dict):
            main = inp.get("command") or inp.get("cmd") or inp.get("file_path") or inp.get("path") or inp.get("pattern") \
                or inp.get("url") or inp.get("query") or json.dumps(inp)[:2000]
            desc = desc or inp.get("description") or ""
        else:
            main = inp
        st = {"t": "tool", "name": name or "?", "desc": trim(desc or "", 200), "input": trim(main if isinstance(main, str)
              else json.dumps(main), 3000), "out": "", "err": False}
        self.steps.append(st)
        if tid is not None:
            self.by_id[tid] = st
        return st

    def result(self, tid, out, err=False):
        st = self.by_id.get(tid)
        if st is not None:
            if isinstance(out, list):
                out = "\n".join(x.get("text", "") if isinstance(x, dict) else str(x) for x in out)
            st.update(out=trim(str(out or ""), 3000), err=bool(err))


def claude_line(tr, e):
    """claude -p --output-format stream-json --verbose"""
    if e.get("type") == "result":
        tr.final = e.get("result") or ""
        if e.get("is_error"):
            raise AgentError(f"claude reported an error ({e.get('subtype')})")
        return
    m = e.get("message")   # system/status events can carry a plain-text message
    for c in m.get("content") if isinstance(m, dict) and isinstance(m.get("content"), list) else []:
        if not isinstance(c, dict):
            continue
        if e.get("type") == "assistant" and c.get("type") == "text":
            tr.text(c.get("text"))
        elif e.get("type") == "assistant" and c.get("type") == "tool_use":
            tr.tool(c.get("id"), c.get("name"), c.get("input") or {})
        elif e.get("type") == "user" and c.get("type") == "tool_result":
            tr.result(c.get("tool_use_id"), c.get("content"), c.get("is_error"))


def codex_line(tr, e):
    """codex exec --json: item.started / item.completed events."""
    it = e.get("item") or {}
    kind = it.get("type") or it.get("item_type")
    if e.get("type") == "item.started" and kind == "command_execution":
        tr.tool(it.get("id"), "shell", it.get("command") or "")
    elif e.get("type") == "item.completed":
        if kind in ("agent_message", "assistant_message"):
            tr.final = it.get("text") or ""
            tr.text(tr.final)
        elif kind == "command_execution":
            if it.get("id") not in tr.by_id:
                tr.tool(it.get("id"), "shell", it.get("command") or "")
            tr.result(it.get("id"), it.get("aggregated_output") or "", (it.get("exit_code") or 0) != 0)
        elif kind == "file_change":
            tr.tool(it.get("id"), "edit", ", ".join(c.get("path", "") for c in it.get("changes") or []))
    elif e.get("type") in ("error", "turn.failed"):
        raise AgentError(str(e.get("message") or e.get("error") or e)[:400])


def gemini_line(tr, e):
    """gemini -p --output-format stream-json"""
    t = e.get("type")
    if t == "message" and e.get("role") == "assistant":
        tr.final += e.get("content") or ""
        if not e.get("delta"):
            tr.text(e.get("content"))
    elif t == "tool_use":
        tr.tool(e.get("tool_id"), e.get("tool_name"), e.get("parameters") or {})
    elif t == "tool_result":
        tr.result(e.get("tool_id"), e.get("output") or (e.get("error") or {}).get("message", ""), e.get("status") == "error")
    elif t == "error":
        raise AgentError(str(e.get("message") or e)[:400])


def opencode_line(tr, e):
    """opencode run --format json"""
    p = e.get("part") or {}
    if e.get("type") == "text":
        tr.final = p.get("text") or ""
        tr.text(tr.final)
    elif e.get("type") == "tool_use":
        st = p.get("state") or {}
        tr.tool(None, p.get("tool"), st.get("input") or {}, st.get("title") or "")
        tr.steps[-1].update(out=trim(str(st.get("output") or ""), 3000), err=st.get("status") == "error")
    elif e.get("type") == "error":
        raise AgentError(str(e.get("error") or e)[:400])


# name -> (argv builder, line parser). AGENT_EXTRA_ARGS go before the prompt. Permission defaults: see README.
ADAPTERS = {
    "claude": (lambda b, x, p: [b or "claude", "-p", "--output-format", "stream-json", "--verbose", "--permission-mode", "auto",
                                *x, p], claude_line),
    "codex": (lambda b, x, p: [b or "codex", "exec", "--json", "--skip-git-repo-check", *x, p], codex_line),
    "gemini": (lambda b, x, p: [b or "gemini", "--output-format", "stream-json", *x, "-p", p], gemini_line),
    "opencode": (lambda b, x, p: [b or "opencode", "run", "--format", "json", *x, p], opencode_line),
}


class AgentError(Exception):
    pass


VERSION = "2.10.0"
READY = {"agent": "", "ready": True, "why": "", "version": VERSION, "at": 0.0}


def readiness():
    """Is the agent CLI there and does it start? Sent with every poll so the board can gray out its AI buttons with the
    reason. Rechecked every 10 minutes and after each failed job."""
    agent = os.environ.get("AGENT", "claude")
    why = ""
    if agent == "command":
        why = "" if os.environ.get("AGENT_CMD") else "AGENT=command needs AGENT_CMD"
    elif agent not in ADAPTERS:
        why = f"unknown AGENT {agent!r}"
    else:
        exe = shutil.which(os.environ.get("AGENT_BIN") or agent)
        if not exe:
            why = f"{os.environ.get('AGENT_BIN') or agent} isn't installed or not on PATH for user {os.environ.get('USER') or os.getuid()}"
        else:
            try:
                p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
                if p.returncode:
                    why = f"`{agent} --version` failed: " + trim((p.stderr or p.stdout).strip()[-300:], 300)
            except (OSError, subprocess.TimeoutExpired) as e:
                why = f"{agent} doesn't start: {e}"
    READY.update(agent=agent, ready=not why, why=why, at=time.time())
    if why:
        log("agent not ready:", why)
    return READY


def failed_hint(agent, stderr):
    """One line for the board: the agent's own error (sign-in, quota, flags) instead of just the exit code."""
    tail = " ".join(trim(stderr.strip(), 4000).split())[-300:]
    if re.search(r"(?i)log ?in|logged|auth|api key|credential|unauthori[sz]ed|401|oauth|token", tail):
        return f"{agent} isn't signed in on the runner machine: {tail}"
    return tail


def run(board, job):
    rid = job["id"]
    agent = os.environ.get("AGENT", "claude")
    cwd = os.environ.get("AGENT_CWD") or str(Path.home())
    timeout = int(os.environ.get("RUN_TIMEOUT", "3600"))
    group = job.get("kind") == "group"
    text = group_prompt(job) if group else prompt(job)
    log("start", rid, f"group of {len(job['runs'])}" if group else job["key"], agent)
    tr, err, pf = Transcript(), "", None
    if agent == "command":
        if not os.environ.get("AGENT_CMD"):
            raise AgentError("AGENT=command needs AGENT_CMD")
        pf = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
        pf.write(text)
        pf.close()
        cmd = os.environ["AGENT_CMD"].replace("{prompt_file}", shlex.quote(pf.name))
        p = subprocess.Popen(cmd, shell=True, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL if "{prompt_file}" in os.environ["AGENT_CMD"] else subprocess.PIPE)
        if p.stdin:
            p.stdin.write(text)
            p.stdin.close()
        parser = None
    else:
        if agent not in ADAPTERS:
            raise AgentError(f"unknown AGENT {agent!r}: use {', '.join(ADAPTERS)} or command")
        build, parser = ADAPTERS[agent]
        argv = build(os.environ.get("AGENT_BIN"), [x.replace("{run_id}", rid) for x in shlex.split(os.environ.get("AGENT_EXTRA_ARGS", ""))], text)
        p = subprocess.Popen(argv, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    board.post(f"/api/runner/start/{rid}")
    errbuf = []
    threading.Thread(target=lambda: errbuf.append(p.stderr.read()), daemon=True).start()
    timed_out = []
    killer = threading.Timer(timeout, lambda: (timed_out.append(1), p.kill()))
    killer.start()
    raw, last = [], 0.0
    try:
        for line in p.stdout:
            if parser is None:
                raw.append(line)
            else:
                try:
                    e = json.loads(line)
                except ValueError:
                    if line.strip():
                        tr.text(line)
                    continue
                if not isinstance(e, dict):
                    continue
                try:
                    parser(tr, e)
                except AgentError as x:
                    err = str(x)
                except Exception as x:   # one odd event must not kill the run (and every incident of a bulk run with it)
                    log("skipped an agent event:", x, line[:200])
            if time.time() - last > 3:
                last = time.time()
                try:
                    board.post(f"/api/runner/progress/{rid}", {"log": tr.steps[-400:] if parser else
                                                               [{"t": "text", "text": trim("".join(raw), 20000)}]})
                except Exception as x:
                    log("progress post failed:", x)
        p.wait()
    finally:
        killer.cancel()
        if pf:
            os.unlink(pf.name)
    if timed_out:
        err = f"stopped after {timeout // 60} min. " + err
    if parser is None:
        tr.final = "".join(raw)
        tr.text(tr.final[-20000:])
    stderr = "".join(errbuf)
    outcome, summary, ask = parse_outcome(tr.final)
    if p.returncode and not err:
        err = f"{agent} exited {p.returncode}: " + (failed_hint(agent, stderr) or "no error output")
    if err:
        READY["at"] = 0
    ferr = err[-800:] if (err and (p.returncode or not tr.final)) else ""
    if group:   # one finish per incident: its own outcome block; the transcript stays on the lead run
        for r, (o, sm, a) in zip(job["runs"], parse_group(tr.final, len(job["runs"]))):
            board.post(f"/api/runner/finish/{r['id']}", {"outcome": o, "summary": trim(sm, 6000), "err": ferr, "ask": trim(a, 1000),
                                                         "log": tr.steps[-400:] if r["id"] == rid else []})
        log("done", rid, "group", f"rc={p.returncode}")
        return
    board.post(f"/api/runner/finish/{rid}", {"outcome": outcome, "summary": trim(summary, 6000), "log": tr.steps[-400:],
                                             "err": ferr, "ask": trim(ask, 1000)})
    log("done", rid, outcome, f"rc={p.returncode}")


BRIEF_ARGV = {  # tool-less, one-shot text answer for AI briefs (short panel summaries)
    "claude": lambda b, p: [b or "claude", "-p", p, "--tools", "", "--model", os.environ.get("BRIEF_MODEL", "haiku"),
                            "--no-session-persistence", "--output-format", "text"],
    "codex": lambda b, p: [b or "codex", "exec", "--skip-git-repo-check", "--sandbox", "read-only", p],
    "gemini": lambda b, p: [b or "gemini", "-p", p],
    "opencode": lambda b, p: [b or "opencode", "run", p],
}


def brief(board, job):
    """Writes one AI brief, pushing the text so far to the board about once a second."""
    bid, out, err, last, tmp = job["id"], [], "", 0.0, None
    agent = os.environ.get("AGENT", "claude")
    log("brief", bid)
    try:
        if agent == "command" or agent not in BRIEF_ARGV:
            if not os.environ.get("AGENT_CMD"):
                raise AgentError("AGENT=command needs AGENT_CMD")
            p = subprocess.Popen(os.environ["AGENT_CMD"].replace("{prompt_file}", "/dev/stdin"), shell=True, text=True,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.stdin.write(job["prompt"])
            p.stdin.close()
        else:
            tmp = tempfile.mkdtemp(prefix="lw-brief-")  # empty cwd: no project instructions or memory; kept until the agent exits
            p = subprocess.Popen(BRIEF_ARGV[agent](os.environ.get("AGENT_BIN"), job["prompt"]), cwd=tmp, text=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        errbuf = []
        threading.Thread(target=lambda: errbuf.append(p.stderr.read()), daemon=True).start()
        killer = threading.Timer(int(os.environ.get("BRIEF_TIMEOUT", "120")), p.kill)
        killer.start()
        for line in p.stdout:
            out.append(line)
            if time.time() - last > 1:
                last = time.time()
                board.post(f"/api/runner/brief/{bid}", {"text": "".join(out).strip()})
        p.wait()
        killer.cancel()
        if p.returncode and not out:
            time.sleep(0.2)   # let the stderr reader finish
            err = f"{agent} exited {p.returncode}: " + (failed_hint(agent, "".join(errbuf)) or "no error output")
            READY["at"] = 0
    except Exception as e:
        err = f"runner error: {e}"
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    board.post(f"/api/runner/brief/{bid}", {"text": "".join(out).strip(), "err": err[:400], "done": True})
    log("brief done", bid, err or "ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env", help="KEY=VALUE file (e.g. the one `setup.py runner-env` wrote)")
    ap.add_argument("--once", action="store_true", help="claim and run queued jobs once, then exit")
    ap.add_argument("--lock", help="single-instance lock file (default: <env>.lock); a second runner exits quietly")
    a = ap.parse_args()
    if a.env:
        load_env(a.env)
    lock = a.lock or (a.env + ".lock" if a.env else None)
    if lock and not a.once:
        lf = open(lock, "w")
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            sys.exit(0)  # another runner already holds the lock: start it as often as you like (login hooks, cron)
    url, token = os.environ.get("LOGWATCH_URL"), os.environ.get("AI_RUNNER_TOKEN")
    if not url or not token:
        sys.exit("LOGWATCH_URL and AI_RUNNER_TOKEN are required (see --help)")
    if url.startswith("http://") and not re.match(r"http://(localhost|127\.|\[::1\])", url):
        log("warning: talking to the board over plain HTTP; the runner token crosses the network unencrypted")
    board = Board(url, token)
    poll = int(os.environ.get("POLL_SECONDS", "10"))
    log("runner up, pid", os.getpid(), "agent", os.environ.get("AGENT", "claude"))
    runs, active = queue.Queue(), set()

    def worker():  # "Resolve with AI" runs, one at a time; briefs get their own threads meanwhile
        while True:
            job = runs.get()
            try:
                run(board, job)
            except Exception as e:
                log("run failed", job.get("id"), e)
                try:
                    for r in job.get("runs") or [job]:
                        board.post(f"/api/runner/finish/{r['id']}", {"err": f"runner error: {e}"[:800]})
                except Exception:
                    pass
            active.discard(job["id"])
            runs.task_done()

    threading.Thread(target=worker, daemon=True).start()
    while True:
        try:
            if time.time() - READY["at"] > 600:
                readiness()
            for job in board.post("/api/runner/claim", {**{k: READY[k] for k in ("agent", "ready", "why", "version")}, "groups": 1}) or []:
                if job.get("kind") == "brief":
                    threading.Thread(target=brief, args=(board, job), daemon=True).start()
                elif job["id"] not in active:
                    active.add(job["id"])
                    runs.put(job)
        except Exception as e:
            log("poll failed:", e)
            time.sleep(30)
        if a.once:
            runs.join()
            break
        time.sleep(poll)

if __name__ == "__main__":
    main()
