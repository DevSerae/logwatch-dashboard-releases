"""VictoriaLogs helpers shared by the board, the worker and the collectors."""
import datetime as dt
import json
import time

import httpx

from settings import VL


def vl(query, start, end, limit=5000):
    r = httpx.post(f"{VL}/select/logsql/query", timeout=120,
                   data={"query": query, "start": start, "end": end, "limit": str(limit)})
    r.raise_for_status()
    return [json.loads(line) for line in r.text.splitlines() if line.strip()]


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ms_iso(ms):
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).isoformat(timespec="milliseconds")


def vl_ts(row):
    try:
        return dt.datetime.fromisoformat(row["_time"].replace("Z", "+00:00")).timestamp()
    except Exception:
        return time.time()


def vl_push(rows, stream="type,hostname", msg="msg", time_field="time"):
    if rows:
        for i in range(0, len(rows), 20000):
            httpx.post(f"{VL}/insert/jsonline", params={"_stream_fields": stream, "_msg_field": msg, "_time_field": time_field},
                       content="\n".join(json.dumps(r) for r in rows[i:i + 20000]), timeout=120).raise_for_status()
