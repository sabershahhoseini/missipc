# Telegram SSH Bot

Drive your servers from Telegram: a live terminal, multiple sessions, key auth,
file transfer, monitoring with alerts, and authenticator-app 2FA.

## Features

- **Live interactive terminal** per server, with VT100 rendering, button
  controls (arrows, Ctrl keys, Esc/Tab), screenshots, and multiple sessions
  you can switch between.
- **Key auth**: generate or import ed25519 keys, install them on a server in
  one tap, import existing private keys.
- **Saved hosts** with optional jump host and tmux session attach.
- **File transfer**: send a file to upload it, `/get path` to download.
- **Broadcast commands** across every open session or a set of saved hosts.
- **Monitoring**: disk/service/load/memory/HTTP/custom checks with anti-spam
  alerting, mute windows, a dead man's switch heartbeat, and a quick
  CPU/RAM/disk dashboard per host.
- **Security**: mandatory authenticator-app 2FA with a sliding unlock window,
  host-key pinning (refuses on change — MITM protection), confirmation
  prompts before destructive-looking commands, and an audit log.

## Project structure

```
bot.py                     entry point — run this
app/                        bot package
  bot.py                    Telegram handlers
  auth.py                   2FA (TOTP) + unlock window
  config.py                 settings (env vars / config file)
  monitor.py                checks, alerting, dashboard
  sshconn.py                SSH connection/key plumbing
  store.py                  JSON store + audit log
  terminal.py               VT100 terminal sessions, screenshots
deploy/
  sshbot.service            systemd unit
  bot.yaml.example          config file template
data/                        created at runtime — keys, 2FA secrets, audit log (gitignored)
```

## Setup

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
export BOT_TOKEN="123456:ABC..."          # from @BotFather
export ALLOWED_USERS="11111111"           # your numeric Telegram ID (ask @userinfobot)
python bot.py
```

Then send `/start` to your bot. It asks you to set up 2FA first: send `/2fa`,
add the setup key (or scan the QR) in your authenticator app, and send the
6‑digit code. After that, the bot locks itself after 15 minutes without
activity; just send a fresh code to unlock.

For running it permanently, see `deploy/sshbot.service`.

### Config file instead of env vars

Any setting below can go in a YAML file instead of exporting env vars every
time:

```bash
cp deploy/bot.yaml.example bot.yaml   # edit it
python bot.py --config bot.yaml
# or: python bot.py bot.yaml
# or: CONFIG_FILE=bot.yaml python bot.py
```

```yaml
bot:
  token: "123456:ABC..."
  allowed_users: [11111111]

security:
  unlock_minutes: 15

sessions:
  idle_timeout_min: 30
```

See `deploy/bot.yaml.example` for every section. Real environment variables
still take priority over the file, so you can mix both (e.g. keep the token
out of the file and export `BOT_TOKEN` separately).

## Settings

Env var always wins; otherwise falls back to the YAML path, then the default.

| Env var | YAML path | Default | Meaning |
|---|---|---|---|
| `BOT_TOKEN` | `bot.token` | required | Bot token from @BotFather |
| `ALLOWED_USERS` | `bot.allowed_users` | required | Telegram user IDs (list or comma string) |
| `ALERT_CHAT_IDS` | `bot.alert_chat_ids` | = allowed users | Where monitoring alerts go |
| `DATA_DIR` | `data_dir` | `data` | Hosts, keys, pinned host keys, 2FA secrets, audit log |
| `REQUIRE_2FA` | `security.require_2fa` | `true` | Set to `false`/`0` to allow use without 2FA (not recommended) |
| `UNLOCK_MINUTES` | `security.unlock_minutes` | `15` | Unlock window, extended by each action |
| `IDLE_TIMEOUT_MIN` | `sessions.idle_timeout_min` | `30` | Close sessions with no input or output for this long (`0` = never) |
| `TERM_SIZE` | `sessions.term_size` | `wide` | `wide` (80×24) or `narrow` (46×22, phones) |
| `TMUX_SESSION` | `sessions.tmux_session` | `tgbot` | tmux session name for hosts with tmux on |
| `REMIND_EVERY_MIN` | `monitoring.remind_every_min` | `60` | Repeat interval for alerts that stay failing |
| `HEALTHCHECK_URL` | `monitoring.healthcheck_url` | – | Pinged on `healthcheck_interval` (dead man's switch, e.g. healthchecks.io) |
| `HEALTHCHECK_INTERVAL` | `monitoring.healthcheck_interval` | `300` | Seconds between heartbeat pings |
| `FONT_PATH` | `font_path` | auto | Monospace TTF for screenshots |
| `CONFIG_FILE` | – | – | Path to the YAML config file (same as `--config`) |

## Quick tour

- `/ssh root:pass@1.2.3.4:22` connects in one go (the message is deleted).
  `/ssh root@1.2.3.4` asks only for the password; `/ssh web1` uses a saved host.
  Options: `-J jumphost`, `key=name`, `tmux`.
- Type normally to send commands to the active session. Buttons give you Esc,
  Tab, arrows, Ctrl keys, snippets, dashboard, screenshot and the full log.
- `/sessions`, `/switch N`, `/stop N`, `/stop all`.
- After connecting with a password, tap **🔑 Use key auth**: the bot generates
  an ed25519 key, installs it on the server and switches the saved host to it.
- Send a file to upload it to the active server (caption = target path).
  `/get path` downloads.
- `/all cmd` runs on every open session; `/run web1,db1 cmd` or `/run all cmd`
  runs on saved key-auth hosts.
- `/checks` → **➕ Add check**: disk, service, load, memory, HTTP or any custom
  command (exit 0 = OK). Alerts fire after 2 failures in a row, remind hourly,
  and announce recovery. `/status`, `/mute web1 2h`.
- `/help` lists everything.

## Security notes

- Keys, 2FA secrets and the audit log live in `DATA_DIR` (mode 700). Anyone
  with that directory and the bot token controls every server the bot can
  reach: run the bot on a machine you trust, ideally not one it monitors.
- Prefer key auth. Passwords you type pass through Telegram's servers (bot
  chats aren't end-to-end encrypted), even though the bot deletes them.
- Host keys are pinned on first connect. If a key changes, the connection is
  refused before any credentials are sent; `/forget host:port` (requires a
  2FA code) clears a pin after a legitimate reinstall.
- For monitoring, consider a dedicated low-privilege user on each server.
- Dangerous-looking commands (`rm -r`, `reboot`, `mkfs`, `dd of=/dev/…`, …)
  ask for confirmation first. Input typed at password prompts is logged as
  `[hidden]` in the audit log.
- This is a safety net against mistakes, not a security boundary against a
  determined attacker who already controls your Telegram account or bot
  token — treat both of those as equivalent to root on every server it reaches.

## License

MIT — see [LICENSE](LICENSE).
