# AI runner ("Resolve with AI")

Optional module `ai`. With it on, open incidents get a **Resolve with AI** button. The board queues a run and the
runner (this folder) picks it up, runs your AI agent CLI headless with the incident as the prompt, and streams the
transcript back. You watch it live on the board at `/ai/<id>`, then press **Resolve** yourself if the fix holds.

The runner only makes outbound HTTP(S) calls to the board. It needs:

- Python 3.8+, standard library only.
- An agent CLI that is installed and logged in: Claude Code, Codex, Gemini CLI, OpenCode, or anything you can wrap
  in a shell command.
- The network and SSH access the agent needs to actually fix things. Run it where your agent normally works.

## Setup

1. On the board host, enable the module and create a runner env file:
   ```
   python3 setup.py modules --enable ai
   python3 setup.py runner-env --url https://logwatch.example.com --out runner.env
   python3 setup.py render && docker compose up -d && docker compose restart board worker
   ```
2. Copy `runner.py` and `runner.env` to the runner machine. Keep `runner.env` mode 600 because it holds the token.
3. Add your agent settings to `runner.env` (see below), then test with `python3 runner.py --env runner.env --once`.
4. Run it permanently, using one of:
   - systemd: `logwatch-ai-runner.service`
   - `tmux`
   - `pm2 start runner.py --interpreter python3 -- --env runner.env`
   - a container entrypoint

   - no service manager (e.g. inside a container): start it from a login/session hook, as often as you like:
     `setsid nohup python3 runner.py --env runner.env >>runner.log 2>&1 </dev/null &`

   Only one runner per env file runs: it holds `runner.env.lock` (or `--lock FILE`), and a second copy exits quietly.
   The board shows "runner not seen" when no runner has polled in the last 90 s. "poll failed: Connection refused"
   while the board restarts is normal; the runner keeps retrying.

   If the runner reaches the board over a VPN/overlay (Tailscale, NetBird, …), use the board's overlay address in
   `LOGWATCH_URL` and make sure `board.allow_cidrs` includes the runner's address.

## Agents

| `AGENT=` | Command run | Default autonomy |
|---|---|---|
| `claude` (default) | `claude -p --output-format stream-json --verbose --permission-mode auto … <prompt>` | `auto`: a classifier approves safe actions |
| `codex` | `codex exec --json --skip-git-repo-check … <prompt>` | Your Codex config. Add e.g. `-s workspace-write` or `--approve-for-me` |
| `gemini` | `gemini --output-format stream-json … -p <prompt>` | Your Gemini config. Add e.g. `--approval-mode auto_edit` or `yolo` |
| `opencode` | `opencode run --format json … <prompt>` | Your OpenCode config/agent permissions |
| `command` | `AGENT_CMD`. `{prompt_file}` is replaced with a temp file path, otherwise the prompt goes to stdin | Whatever the command does |

`AGENT_EXTRA_ARGS` is inserted before the prompt, for example `--model …` or a permission flag. A headless agent can't
ask before acting, so **choose autonomy deliberately**:

- Read-only/plan modes are safe, but the agent can only diagnose.
- Full-bypass modes (`--dangerously-*`, `yolo`) let the agent do anything its account can.

The prompt tells the agent not to make destructive, production or outward-facing changes without approval, but that's
an instruction, not a sandbox. Give the runner's account only the access you're comfortable an agent having.

Agent CLIs change their JSON event formats from time to time. If the live transcript looks empty but the run finishes,
the summary still arrives. Try `AGENT=command` with `AGENT_CMD='claude -p "$(cat {prompt_file})"'` (or similar)
for plain-text output.

## Approvals

A headless agent can't stop mid-run to ask, so it asks at the end. When a fix needs one action the operator must OK
(a production restart, a major upgrade), the agent prepares what is safe, then answers `needs_approval` with that one
action on an `APPROVAL:` line. The board then:

- tags the item **AI needs your OK** and shows the action with **Approve** / **Deny** (on the item and in its drawer)
- shows a header chip with the number of approvals waiting (admins only)
- on **Approve**, queues a new run whose prompt says exactly that action is approved (nothing beyond it); on **Deny**,
  notes it in the item's history. A new run supersedes an unanswered request.

Updated runners only offer `needs_approval` when the board says it understands it (`board.approvals` in the claim),
so an older board keeps getting `fixed` / `not_fixed`. An older runner never asks.

To pre-approve routine work (e.g. "image updates within the same major version, after backing up the config"), say
so in `AGENT_NOTES`: the agent then does it without asking and asks only for the rest.

## Environment notes

Put durable knowledge about your network into `AGENT_NOTES` (a markdown file) or the agent's own memory/instructions in
`AGENT_CWD`. Useful things to include:

- Which hosts exist and how to reach them.
- What's production.
- Who to ask.

The prompt includes the incident, its board history and related log lines. Strings that look like `key=…` or `token: …`
are redacted from the transcript before it's sent to the board.

## Optional chat link

If your agent has a web chat UI that can open a session by id, set `ai.chat_url` in `config.yaml`, e.g.
`https://chat.example.com/session/{run_id}`. The board then shows an **Open chat ↗** link next to each run. For that to
work the agent session must use the run id: `{run_id}` in `AGENT_EXTRA_ARGS` is replaced per run, e.g. Claude Code:
`AGENT_EXTRA_ARGS=--session-id {run_id}` (run the agent in the directory your chat UI's project points at, `AGENT_CWD`).
