"""Chat with Claude via the Claude Code CLI, authenticated with your Pro/Max
subscription login (run `claude login` once on this machine) -- no API key,
usage comes out of your subscription quota, not pay-as-you-go API billing.

Conversations are named and persist in the JSON store, each holding a Claude
Code session id so --resume keeps its context; you can keep several and
switch between them. Each turn is also kept locally so the whole
conversation can be pulled out as a transcript.

What Claude may actually do is set in config (claude.mode,
claude.allowed_tools), not at runtime -- the default is a read-only tool
whitelist in an isolated, otherwise-empty working directory. Since this runs
non-interactively there's no TTY to approve a permission prompt, so anything
outside the whitelist fails instead of running.
"""
import asyncio
import json
import logging
import os
import shlex
import time

from . import config

log = logging.getLogger("missipc.claude")

WORKDIR = os.path.join(config.DATA_DIR, "claude_chat")
MAX_TURNS = 100                  # kept per conversation, for the transcript
MAX_TRANSCRIPT_BYTES = 200_000   # and a byte budget, so data.json stays sane

_locks: dict[str, asyncio.Lock] = {}


# ---------------- conversations ----------------

def for_chat(store, chat_id) -> dict:
    return {cid: c for cid, c in store["claude_chats"].items() if c.get("chat_id") == chat_id}


def active(store, chat_id):
    """Returns (conv_id, conv) for the chat's current conversation, or (None, None)."""
    cid = store["claude_active"].get(str(chat_id))
    conv = store["claude_chats"].get(cid) if cid else None
    return (cid, conv) if conv else (None, None)


def create(store, chat_id, name: str = "") -> tuple[str, dict]:
    cid = str(store["next_claude_id"])
    store["next_claude_id"] += 1
    now = int(time.time())
    conv = {"chat_id": chat_id, "name": name.strip() or f"chat {cid}", "session_id": None,
            "created": now, "last": now, "turns": []}
    store["claude_chats"][cid] = conv
    store["claude_active"][str(chat_id)] = cid
    store.save()
    return cid, conv


def ensure(store, chat_id) -> tuple[str, dict]:
    cid, conv = active(store, chat_id)
    return (cid, conv) if conv else create(store, chat_id)


def switch(store, chat_id, cid: str) -> dict | None:
    conv = store["claude_chats"].get(cid)
    if not conv or conv.get("chat_id") != chat_id:
        return None
    store["claude_active"][str(chat_id)] = cid
    store.save()
    return conv


def rename(store, chat_id, cid: str, name: str) -> bool:
    conv = store["claude_chats"].get(cid)
    if not conv or conv.get("chat_id") != chat_id or not name.strip():
        return False
    conv["name"] = name.strip()[:40]
    store.save()
    return True


def delete(store, chat_id, cid: str) -> bool:
    conv = store["claude_chats"].get(cid)
    if not conv or conv.get("chat_id") != chat_id:
        return False
    del store["claude_chats"][cid]
    if store["claude_active"].get(str(chat_id)) == cid:
        store["claude_active"].pop(str(chat_id), None)
    store.save()
    return True


def transcript(store, cid: str) -> str:
    conv = store["claude_chats"].get(cid)
    if not conv:
        return ""
    head = time.strftime("%Y-%m-%d %H:%M", time.localtime(conv["created"]))
    lines = [f"{conv['name']} — started {head}", "=" * 60, ""]
    for t in conv["turns"]:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(t["t"]))
        lines += [f"[{stamp}] you:", t["q"], "", f"[{stamp}] claude:", t["a"], "", "-" * 60, ""]
    return "\n".join(lines)


def _record(store, conv: dict, q: str, a: str):
    conv["turns"].append({"t": int(time.time()), "q": q, "a": a})
    conv["last"] = int(time.time())
    turns = conv["turns"]
    del turns[:max(0, len(turns) - MAX_TURNS)]
    while len(turns) > 1 and sum(len(t["q"]) + len(t["a"]) for t in turns) > MAX_TRANSCRIPT_BYTES:
        turns.pop(0)
    store.save()


# ---------------- running it ----------------

def _cmd(text: str, session_id: str | None) -> list[str]:
    cmd = [config.CLAUDE_BIN, "-p", text, "--output-format", "json"]
    if session_id:
        cmd += ["--resume", session_id]
    if config.CLAUDE_MODE:
        cmd += ["--permission-mode", config.CLAUDE_MODE]
    if config.CLAUDE_ALLOWED_TOOLS:
        cmd += ["--allowed-tools", config.CLAUDE_ALLOWED_TOOLS]
    if config.CLAUDE_EXTRA_ARGS:
        cmd += shlex.split(config.CLAUDE_EXTRA_ARGS)
    return cmd


async def ask(store, chat_id: int, text: str) -> tuple[bool, str]:
    """Send one message to the chat's active conversation. Returns (ok, reply)."""
    os.makedirs(WORKDIR, mode=0o700, exist_ok=True)
    cid, conv = ensure(store, chat_id)
    cmd = _cmd(text, conv.get("session_id"))

    async with _locks.setdefault(cid, asyncio.Lock()):
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
        reply = out.decode(errors="replace").strip() or "(no output)"
        _record(store, conv, text, reply)
        return True, reply

    if data.get("session_id"):
        conv["session_id"] = data["session_id"]

    reply = data.get("result")
    if reply is None:
        reply = data.get("response") or json.dumps(data)[:1500]
    _record(store, conv, text, reply)
    return True, reply
