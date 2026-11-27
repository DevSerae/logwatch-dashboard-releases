"""What's still left to set up, for the board: data/setup-pending.json.

    sudo .venv/bin/python -m installer pending

Written by update.sh after updates, feature installs and settings edits (and by the web installer when it saves), so
work started in an older installer or board (servers not marked installed, required settings left empty) shows up in
the board's Features section instead of being lost. Steps are the installer's own (prompts.steps), as markdown.
"""
import json
import os
import tempfile
import time

from . import configio, prompts
from .schema import ALL_MODULES

OUT = configio.setup.DATA / "setup-pending.json"


def compute(state=None):
    st = state or configio.load()
    on = configio.enabled(st)
    probs = configio.validate(st)
    mods = {}
    for m in sorted(on):
        p = [x for x in probs.get(m, [])]
        mods[m] = {"problems": p, "steps": prompts.steps(st, m), "servers": []}
    try:
        servers = prompts.servers(st)
    except Exception:   # a half-written host list: the problems above already say so
        servers = []
    for e in servers:
        for i in e["items"]:
            if not i["done"] and i["module"] in mods:
                mods[i["module"]]["servers"].append({"id": i["id"], "name": e["name"], "address": e["address"], "os": e["os"],
                                                     "what": i["what"], "cmd": i["cmd"]})
    return {"at": int(time.time()), "version": prompts.version(),
            "modules": {m: x for m, x in mods.items() if x["problems"] or x["servers"]}}


def write(state=None):
    d = compute(state)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=OUT.parent, prefix=".pending-")   # data/ is writable by the containers: no fixed tmp name
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, indent=1)
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT)
    configio.fix_owner()
    return d


def main():
    d = write()
    n = len(d["modules"])
    print(f"{OUT}: {n} feature{'s' if n != 1 else ''} with setup left" + (": " + ", ".join(d["modules"]) if n else ""))
