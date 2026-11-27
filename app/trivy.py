#!/usr/bin/env python3
"""Weekly (module "trivy"): list the images running on each ssh.hosts entry with role "images" (the forced command
only prints `docker ps` image refs), scan them with trivy and write fixable HIGH/CRITICAL counts to /data/trivy.json
for collect.py."""
import json
import subprocess
import time

import remote
from settings import DATA, mod, ssh_hosts

OUT = DATA / "trivy.json"


def images(host):
    out = remote.run(host, "images", timeout=60)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:200])
    # Each line is "<image name>\t<repo@digest>".
    pairs = set()
    for line in out.stdout.splitlines():
        if line.strip():
            name, _, ref = line.strip().partition("\t")
            pairs.add((name, ref or name))
    return sorted(pairs)


def scan(image):
    out = subprocess.run(["trivy", "image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL",
                          "--ignore-unfixed", "--scanners", "vuln", "--cache-dir", str(DATA / "trivy-cache"), image],
                         capture_output=True, text=True, timeout=1800)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[-200:])
    return [v for r in json.loads(out.stdout).get("Results", []) for v in r.get("Vulnerabilities") or []]


def main():
    if not mod("trivy"):
        return
    findings, errors = [], []
    scanned = {}  # ref -> vulns, so an image running on several hosts is scanned once
    for host in [h["name"] for h in ssh_hosts("images")]:
        try:
            imgs = images(host)
        except Exception as e:
            errors.append(f"{host}: {e}")
            continue
        for img, ref in imgs:
            if ref not in scanned:
                try:
                    scanned[ref] = scan(ref)
                except Exception as e:
                    scanned[ref] = None
                    errors.append(f"{host} {img}: {e}")
            vulns = scanned[ref]
            if vulns is None:
                continue
            crit = sum(v["Severity"] == "CRITICAL" for v in vulns)
            high = sum(v["Severity"] == "HIGH" for v in vulns)
            if crit or high:
                top = sorted(vulns, key=lambda v: v["Severity"] != "CRITICAL")[:8]
                detail = "\n".join(f"{v['VulnerabilityID']} {v['PkgName']} {v.get('InstalledVersion', '')} → "
                                   f"{v.get('FixedVersion', '')}" for v in top)
                findings.append({"host": host, "target": img, "crit": crit, "high": high,
                                 "detail": detail + "\nRe-pull the image / update the container."})
    OUT.write_text(json.dumps({"generated": time.time(), "findings": findings, "errors": errors}))


if __name__ == "__main__":
    main()
