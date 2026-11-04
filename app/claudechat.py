"""Chat with Claude via the Claude Code CLI, authenticated with your Pro/Max
subscription login (run `claude login` once on this machine) -- no API key,
usage comes out of your subscription quota, not pay-as-you-go API billing.

Each Telegram chat gets its own Claude Code session (kept alive via
--resume) so the conversation has memory across messages; /newchat starts
over. Runs in an isolated, otherwise-empty working directory so there's
nothing of yours for a tool call to touch, and since this is non-interactive
(-p) there's no TTY to approve a permission prompt anyway -- a tool call
that needs approval just fails safely instead of running.
"""
import asyncio
import json
import logging
import os

from . import config

log = logging.getLogger("missipc.claude")

WORKDIR = os.path.join(config.DATA_DIR, "claude_chat")
_locks: dict[int, asyncio.Lock] = {}


def _lock(chat_id: int) -> asyncio.Lock:
    return _locks.setdefault(chat_id, asyncio.Lock())


async def ask(store, chat_id: int, text: str) -> tuple[bool, str]:
    """Send one message to Claude for this chat. Returns (ok, reply_or_error)."""
    os.makedirs(WORKDIR, mode=0o700, exist_ok=True)
    sessions = store["claude_sessions"]
    session_id = sessions.get(str(chat_id))
    cmd = [config.CLAUDE_BIN, "-p", text, "--output-format", "json"]
    if session_id:
        cmd += ["--resume", session_id]

    async with _lock(chat_id):
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=WORKDIR, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError:
            return False, (f"`{config.CLAUDE_BIN}` isn't installed/on PATH on this server. "
                            "Install the Claude Code CLI and run `claude login` once (Pro/Max, no API key).")
        try:
            out, err = await asyncio.wait_for(proc.communicate(), config.CLAUDE_TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False, f"Claude took longer than {config.CLAUDE_TIMEOUT}s to respond."

    if proc.returncode != 0:
        msg = err.decode(errors="replace").strip() or out.decode(errors="replace").strip()
        log.warning("claude exited %s: %s", proc.returncode, msg[:500])
        return False, msg[:1500] or f"claude exited with status {proc.returncode}"

    try:
        data = json.loads(out.decode())
    except json.JSONDecodeError:
        return True, out.decode(errors="replace").strip() or "(no output)"

    new_session = data.get("session_id")
    if new_session:
        sessions[str(chat_id)] = new_session
        store.save()

    reply = data.get("result")
    if reply is None:
        reply = data.get("response") or json.dumps(data)[:1500]
    return True, reply


def reset(store, chat_id: int):
    store["claude_sessions"].pop(str(chat_id), None)
    store.save()
