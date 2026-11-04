# Telegram PC

Your laptop, in your pocket. If you're away from it and need to SSH into a
server, or just want to ask Claude something, this bot is the stand-in:
a live terminal and a Claude chat, both from Telegram.

## What it does

- **SSH from your phone** — a real interactive terminal per server (VT100
  rendering, button controls, screenshots), multiple sessions at once, saved
  hosts, key generation/install, jump hosts, file upload/download, and
  broadcasting a command to several servers at once.
- **Chat with Claude** — `/chat` turns the conversation into a Claude chat
  instead of a terminal. Uses your Claude Code CLI login (Pro/Max
  subscription), not an API key.
- **Monitoring** — disk/service/load/memory/HTTP/custom checks with alerts,
  mute windows, and a quick dashboard, so you notice problems before you'd
  normally be at a keyboard to.
- **Locked down** — mandatory 2FA, host-key pinning, confirmation before
  destructive-looking commands, an audit log.

## Setup

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
export BOT_TOKEN="123456:ABC..."    # from @BotFather
export ALLOWED_USERS="11111111"     # your numeric Telegram ID (ask @userinfobot)
python bot.py
```

Send `/start` to your bot. It'll ask you to set up 2FA first (`/2fa` — scan
the QR, send the 6-digit code). After that it locks itself after 15 minutes
idle; send a fresh code to unlock.

To run it permanently, see `deploy/sshbot.service`.

To use `/chat`, install the Claude Code CLI on the same machine and log in
once with your subscription — no API key needed:

```bash
npm install -g @anthropic-ai/claude-code
claude login
```

### Config file, instead of env vars

```bash
cp deploy/bot.yaml.example bot.yaml   # edit it
python bot.py --config bot.yaml
```

```yaml
bot:
  token: "123456:ABC..."
  allowed_users: [11111111]
```

Real environment variables still override the file. See
`deploy/bot.yaml.example` for every setting.

## Using it

**SSH:** `/ssh user:pass@host:port` connects in one go (message deleted);
`/ssh user@host` asks for the password; `/ssh web1` uses a saved host. Type
normally to send input to the open session. `/sessions`, `/switch N`,
`/stop N`. After a password login, tap **🔑 Use key auth** to switch that
host to key auth permanently. Send a file to upload it, `/get path` to
download. `/all cmd` runs on every open session.

**Claude:** `/chat` to start — type normally, it replies in-chat and
remembers context. `/newchat` resets it, `/endchat` goes back to SSH input.

**Monitoring:** `/checks` → ➕ Add check (disk, service, load, memory, HTTP,
or any command). Alerts after 2 failed runs in a row, and on recovery.
`/status`, `/mute host 2h`.

`/help` lists every command.

## Security notes

- Anyone with `DATA_DIR` (keys, 2FA secrets, audit log) and the bot token
  controls every server this bot can reach — run it on a machine you trust.
- Prefer key auth over passwords: Telegram chats aren't end-to-end
  encrypted, even though the bot deletes password messages.
- Host keys are pinned on first connect; a changed key refuses the
  connection outright (MITM protection). `/forget host:port` clears a pin.
- This is a safety net against mistakes, not a defense against someone who
  already controls your Telegram account or bot token — treat both as
  equivalent to root on everything this bot reaches.

## License

MIT — see [LICENSE](LICENSE).
