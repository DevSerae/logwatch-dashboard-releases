# Webhook: raise board items from anything

Turn it on with `python3 setup.py modules --enable webhook`, then run `python3 setup.py secret INGEST_TOKEN --generate`,
`python3 setup.py render`, `docker compose up -d` and `docker compose restart board worker`.

`POST /api/ingest` with `Authorization: Bearer <INGEST_TOKEN>` and a JSON object, or a list of up to 200:

| Field | |
|---|---|
| `title` | required (or `key`) |
| `detail` | optional text |
| `severity` | `info` \| `warning` (default) \| `error` \| `critical` |
| `source` | short name shown on the item, default `webhook` |
| `key` | stable id. Same key = same item, updated. Default: derived from source + title |
| `kind` | `alert` (default, a board item) or `event` (Events tab only) |
| `clear` | `true` closes the open item with this key |

```bash
TOKEN=$(grep ^INGEST_TOKEN= secrets/secrets.env | cut -d= -f2-)
curl -fsS https://logwatch.example.com/api/ingest -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"backup-nightly","source":"backup","severity":"error","title":"Nightly backup failed","detail":"exit 2"}'
# later, when it works again:
curl -fsS https://logwatch.example.com/api/ingest -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"backup-nightly","clear":true}'
```

Ideas:

- Cron jobs: `|| curl …` on failure, clear on success.
- Uptime Kuma, Grafana and Alertmanager webhooks, through a small relay that maps their payload to the fields above.
- Replication checks and certificate renewals.

Keep the token on the sending machine in a file only root can read. Rotate it with `setup.py secret INGEST_TOKEN --generate`
plus `docker compose restart board`.
