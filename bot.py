"""Telegram SSH bot — entry point and all Telegram handlers.  Run:  python bot.py"""
import asyncio
import html
import io
import logging
import os
import re
import secrets
import shlex
import time
from functools import wraps

from telegram import (BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, InputFile,
                      LinkPreviewOptions, Update)
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler, ContextTypes,
                          MessageHandler, filters)

import config
import sshconn
from auth import Auth
from monitor import DASH_CMD, INTERVALS, TYPES, Monitor, build_check, format_dash
from store import Store
from terminal import KEYS, PASSWORD_PROMPT, SessionManager, Session, ago, is_dangerous, tg

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("asyncssh").setLevel(logging.WARNING)
log = logging.getLogger("sshbot")

HTML = ParseMode.HTML
NOPREVIEW = LinkPreviewOptions(is_disabled=True)
CODE_RE = re.compile(r"^\s*(\d{3})\s?(\d{3})\s*$")
MB = 1024 * 1024

store = Store()
auth = Auth(store)
mgr = SessionManager()
APP: Application | None = None
monitor = Monitor(store, lambda: APP.bot)


# ======================================================================
# small helpers
# ======================================================================

def B(text, data):
    return InlineKeyboardButton(text, callback_data=data)


def KB(*rows):
    return InlineKeyboardMarkup([list(r) for r in rows if r])


def esc(s) -> str:
    return html.escape(str(s))


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def cmd_arg(update: Update) -> str:
    """Everything after the /command, raw (keeps spaces and quotes)."""
    parts = (update.message.text or "").split(maxsplit=1)
    return parts[1].strip() if len(parts) > 1 else ""


async def send(bot, chat_id, text, kb=None):
    return await tg(lambda: bot.send_message(chat_id, text, parse_mode=HTML, reply_markup=kb,
                                             link_preview_options=NOPREVIEW))


async def try_delete(bot, chat_id, mid) -> bool:
    try:
        await bot.delete_message(chat_id, mid)
        return True
    except Exception:
        return False


async def panel(ctx, chat_id, slot, text, kb=None):
    """Edit the message remembered under `slot`, or send a new one and remember it."""
    mid = ctx.chat_data.get(slot)
    if mid:
        try:
            await tg(lambda: ctx.bot.edit_message_text(text, chat_id=chat_id, message_id=mid, parse_mode=HTML,
                                                       reply_markup=kb, link_preview_options=NOPREVIEW))
            return
        except BadRequest as e:
            if "not modified" in str(e).lower():
                return
    m = await send(ctx.bot, chat_id, text, kb)
    if m:
        ctx.chat_data[slot] = m.message_id


def is_terminal_msg(mid) -> bool:
    return any(s.msg_id == mid for s in list(mgr.by_id.values()) + list(mgr.closed.values()))


async def show(q, ctx, text, kb=None):
    """Replace the tapped message with a view — but never overwrite a live terminal."""
    if q.message and not is_terminal_msg(q.message.message_id):
        try:
            await q.edit_message_text(text, parse_mode=HTML, reply_markup=kb, link_preview_options=NOPREVIEW)
            return
        except BadRequest as e:
            if "not modified" in str(e).lower():
                return
    await send(ctx.bot, q.message.chat.id, text, kb)


def find_saved(c: dict) -> str | None:
    for name, h in store["hosts"].items():
        if h["host"] == c.get("host") and h["port"] == c.get("port") and h["user"] == c.get("user"):
            return name
    return None


def apply_saved(d: dict):
    name = d.get("name") or find_saved(d)
    if name and name in store["hosts"]:
        h = store["hosts"][name]
        d["name"] = name
        for k in ("key", "jump", "tmux"):
            if d.get(k) is None:
                d[k] = h.get(k)


# ======================================================================
# 2FA gate
# ======================================================================

def lock_text(uid) -> str:
    if config.REQUIRE_2FA and not auth.enabled(uid):
        return "🔐 <b>Two-factor setup required</b>\nSend /2fa to link your authenticator app."
    return "🔒 <b>Locked</b>\nSend the 6-digit code from your authenticator app."


def gated(fn):
    @wraps(fn)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        if uid not in config.ALLOWED:
            return
        if not auth.is_unlocked(uid):
            if update.message:      # the command might contain a password (/ssh u:p@h)
                await try_delete(ctx.bot, update.effective_chat.id, update.message.message_id)
            await send(ctx.bot, update.effective_chat.id, lock_text(uid))
            return
        auth.touch(uid)
        return await fn(update, ctx)
    return wrapper


async def begin_2fa_setup(ctx, chat, uid, user):
    secret, uri = auth.begin_setup(uid, user.username or str(user.id))
    pretty = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    text = ("🔐 <b>Set up your authenticator</b>\n\n"
            "1. In your authenticator app: add account → <i>Enter a setup key</i>\n"
            "2. Account name: <code>SSH Bot</code>\n"
            f"3. Key: <code>{pretty}</code>\n"
            "4. Type: time-based\n\n"
            "(or scan the QR code)\n\n"
            "Then send the 6-digit code it shows. This message gets deleted once you're done.")
    m = None
    try:
        import qrcode
        buf = io.BytesIO()
        qrcode.make(uri).save(buf, "PNG")
        buf.seek(0)
        m = await ctx.bot.send_photo(chat, buf, caption=text, parse_mode=HTML)
    except Exception:
        m = await send(ctx.bot, chat, text)
    if m:
        ctx.chat_data["setup_msg"] = m.message_id
    ctx.chat_data["await_code"] = "setup"


async def ask_code(ctx, chat, action: dict, prompt: str):
    ctx.chat_data["confirm"] = action
    ctx.chat_data["await_code"] = "confirm"
    await send(ctx.bot, chat, f"🔐 {prompt}\nSend your current 6-digit code to confirm.", KB([B("✖ Cancel", "cfc")]))


async def handle_code(update, ctx, code):
    uid, chat = update.effective_user.id, update.effective_chat.id
    mode = ctx.chat_data.get("await_code") or "unlock"
    if mode == "unlock" and not auth.enabled(uid):
        await send(ctx.bot, chat, lock_text(uid))
        return
    ok, err = auth.verify(uid, code)
    if not ok:
        store.audit(uid, "bad_code", mode=mode)
        await send(ctx.bot, chat, f"❌ {esc(err)}")
        return
    ctx.chat_data.pop("await_code", None)
    auth.unlock(uid)
    if mode == "setup":
        mid = ctx.chat_data.pop("setup_msg", None)
        if mid:
            await try_delete(ctx.bot, chat, mid)
        store.audit(uid, "2fa_enabled")
        await send(ctx.bot, chat, f"✅ <b>Two-factor enabled.</b> Unlocked for {config.UNLOCK_MINUTES} min "
                                  "after your last action. When locked, just send a code.")
        await send(ctx.bot, chat, *menu_view(uid, chat))
    elif mode == "confirm":
        action = ctx.chat_data.pop("confirm", None)
        if action:
            await run_confirmed(update, ctx, action)
    else:
        store.audit(uid, "unlock")
        await send(ctx.bot, chat, f"🔓 Unlocked for {config.UNLOCK_MINUTES} min.")
        s = mgr.current(chat)
        if s:
            await s.refresh(repost=True)


async def run_confirmed(update, ctx, action):
    uid, chat = update.effective_user.id, update.effective_chat.id
    kind = action["kind"]
    if kind == "2fa_disable":
        auth.disable(uid)
        store.audit(uid, "2fa_disabled")
        extra = " The bot is locked until you set it up again with /2fa." if config.REQUIRE_2FA else ""
        await send(ctx.bot, chat, "❌ Two-factor disabled." + extra)
    elif kind == "2fa_reset":
        auth.disable(uid)
        store.audit(uid, "2fa_reset")
        await begin_2fa_setup(ctx, chat, uid, update.effective_user)
    elif kind == "forget":
        store["known_hosts"].pop(action["pin"], None)
        store.save()
        store.audit(uid, "forget_hostkey", pin=action["pin"])
        await send(ctx.bot, chat, f"🗑 Forgot the pinned key for <code>{esc(action['pin'])}</code>.\n"
                                  "The next connection pins the new key; check the fingerprint it shows.")


# ======================================================================
# views
# ======================================================================

HELP = """🖥 <b>SSH Bot — commands</b>

<b>Connect</b>
/ssh — wizard  ·  /ssh user:pass@host:port  ·  /ssh user@host  ·  /ssh <i>savedname</i>
   options: <code>-J jumphost</code>  <code>key=name</code>  <code>tmux</code>
/sessions · /switch N · /stop N|all · /term

<b>Work</b>
/all <i>cmd</i> — run on every open session
/run <i>host1,host2|all cmd</i> — run on saved (key-auth) hosts
/snippets · /snip add <i>name cmd</i> · /snip del <i>name</i>
/dash [<i>host|N</i>] · /shot · /get <i>path</i>
Send a file to upload it (caption = remote path)

<b>Hosts &amp; keys</b>
/hosts · /host add <i>name user@host:port</i> [key= jump= tmux=on]
/host set <i>name</i> key=… jump=… tmux=on|off name=…  ·  /host del <i>name</i>
/keys · /keys gen <i>name</i> · /installkey [<i>key</i>]
Import a key: send the file with caption <code>/importkey name [passphrase]</code>
/forget <i>host:port</i> — forget a pinned host key

<b>Monitoring</b>
/checks · /check add · /check del|pause|resume|run <i>id</i>
/status · /mute <i>host|#id</i> [<i>2h</i>] · /unmute <i>host|#id</i>

<b>Security</b>
/2fa · /lock · /audit [<i>n</i>]"""


def menu_view(uid, chat):
    sess = mgr.for_chat(chat)
    checks = store["checks"]
    failing = sum(1 for c in checks if monitor.status_icon(c) == "🔴")
    lock = "🔓 unlocked" if auth.enabled(uid) else "⚠️ 2FA off"
    line = f"{lock} · {len(sess)} session(s) · {len(checks)} check(s)"
    if failing:
        line += f" · 🔴 {failing} failing"
    return (f"🖥 <b>SSH Bot</b>\n{line}",
            KB([B("🔐 Connect", "new"), B(f"⭐ Hosts ({len(store['hosts'])})", "hosts")],
               [B(f"🖥 Sessions ({len(sess)})", "sessions"), B("🩺 Checks", "checks")],
               [B("⚡ Snippets", "snips:a"), B("🔑 Keys", "keys")],
               [B("📋 Status", "status"), B("📜 Audit", "audit"), B("🔒 Lock", "lock")],
               [B("❓ Help", "help")]))


def sessions_view(chat):
    ss = sorted(mgr.for_chat(chat), key=lambda s: s.sid)
    if not ss:
        return "🖥 <b>Sessions</b>\n\nNo open sessions.", KB([B("🔐 Connect", "new"), B("🏠 Menu", "menu")])
    now, act = time.time(), mgr.active.get(chat)
    lines, rows = ["🖥 <b>Sessions</b>", ""], []
    for s in ss:
        mark = "⭐" if s.sid == act else "▫️"
        extra = " · 🔔 new output" if s.unread else ""
        lines.append(f"{mark} <b>[{s.sid}]</b> {esc(s.label)}\n"
                     f"      up {ago(now - s.started)} · idle {ago(now - s.last_input)}{extra}")
        rows.append([B(f"📺 Open [{s.sid}]", f"sw:{s.sid}"), B("📊", f"t:{s.sid}:dash"),
                     B("🛑 Stop", f"st:{s.sid}")])
    rows.append([B("🛑 Stop all", "stall"), B("🔐 New", "new"), B("🏠 Menu", "menu")])
    lines += ["", "<i>/switch N · /stop N · /all &lt;cmd&gt;</i>"]
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def host_line(name, h) -> str:
    auth_s = f"🔑 {esc(h['key'])}" if h.get("key") else "🔒 password"
    extra = (" · 🧵" if h.get("tmux") else "") + (f" · ↪️ {esc(h['jump'])}" if h.get("jump") else "")
    return f"<b>{esc(name)}</b> · <code>{esc(sshconn.label_of(h))}</code> · {auth_s}{extra}"


def hosts_view():
    hosts = store["hosts"]
    lines = ["⭐ <b>Saved hosts</b>", ""]
    if not hosts:
        lines.append("Nothing saved yet. Connect once and tap <b>⭐ Save host</b>, or use /host add.")
    lines += [f"🖥 {host_line(n, h)}" for n, h in hosts.items()]
    lines += ["", "<i>/host add name user@host:port [key=… jump=… tmux=on]</i>"]
    names = list(hosts)
    rows = [[B(f"🖥 {n}", f"hv:{n}") for n in names[i:i + 2]] for i in range(0, len(names), 2)]
    rows.append([B("🏠 Menu", "menu")])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def host_view(name):
    h = store["hosts"].get(name)
    if not h:
        return hosts_view()
    pin = store["known_hosts"].get(sshconn.pin_id(h["host"], h["port"]))
    lines = [f"🖥 {host_line(name, h)}", "",
             f"Host key: {'📌 pinned' if pin else 'not pinned yet'}"]
    auth_label = f"🔑 {h['key']}" if h.get("key") else "🔒 password"
    return "\n".join(lines), KB(
        [B("🔌 Connect", f"ho:{name}"), B("📊 Dash", f"dr:h:{name}")],
        [B(f"Auth: {auth_label}", f"ha:{name}"), B(f"🧵 tmux: {'on' if h.get('tmux') else 'off'}", f"ht:{name}")],
        [B("🗑 Delete", f"hx:{name}"), B("⬅️ Hosts", "hosts"), B("🏠 Menu", "menu")])


def keys_view():
    keys = sshconn.list_keys()
    lines = ["🔑 <b>SSH keys</b> (stored on the bot host)", ""]
    if not keys:
        lines.append("No keys yet. Generate one, then install it on a server with /installkey.")
    for k in keys:
        users = [n for n, h in store["hosts"].items() if h.get("key") == k]
        lines.append(f"🔑 <b>{esc(k)}</b>" + (f" · used by {esc(', '.join(users))}" if users else ""))
    lines += ["", "Import: send the private key file with caption <code>/importkey name [passphrase]</code>"]
    rows = [[B(f"📋 {k}", f"kp:{k}"), B("🗑", f"kx:{k}")] for k in keys]
    rows.append([B("➕ Generate key", "kg"), B("🏠 Menu", "menu")])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def snippets_view(target: str):
    snips = store["snippets"]
    lines = ["⚡ <b>Snippets</b>", ""]
    if not snips:
        lines.append("None yet. Add one: <code>/snip add disk df -h</code>")
    for n, c in snips.items():
        lines.append(f"<b>{esc(n)}</b> · <code>{esc(c[:60])}</code>")
    if snips:
        lines += ["", "Tap to run in " + ("the active session" if target == "a" else f"session [{target}]") + "."]
    names = list(snips)
    rows = [[B(f"▶️ {n}", f"sp:{target}:{n}") for n in names[i:i + 3]] for i in range(0, len(names), 3)]
    rows.append([B("🏠 Menu", "menu")])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


def checks_view():
    return monitor.checks_text(), KB([B("➕ Add check", "ca"), B("🔁 Run all", "crall")],
                                     [B("📋 Status", "status"), B("🏠 Menu", "menu")])


def audit_text(n=25) -> str:
    recs = store.read_audit(n)
    if not recs:
        return "📜 <b>Audit log</b>\n\nEmpty."
    lines = ["📜 <b>Audit log</b> (newest last)", ""]
    for r in recs:
        t = time.strftime("%m-%d %H:%M", time.localtime(r.get("t", 0)))
        details = " ".join(f"{k}={v}" for k, v in r.items() if k not in ("t", "uid", "event"))
        lines.append(f"<code>{t}</code> <b>{esc(r.get('event'))}</b> {esc(details[:120])}")
    return "\n".join(lines)


# ======================================================================
# connecting
# ======================================================================

def next_step(d):
    for k in ("host", "port", "user"):
        if not d.get(k):
            return k
    return None if d.get("key") else "password"


def wizard_view(d, step, error=None):
    def row(name, key):
        if d.get(key):
            return f"✅ {name}: <code>{esc(d[key])}</code>"
        if step == key:
            return f"✏️ <b>{name}</b>: <i>type it below…</i>"
        return f"▫️ {name}"

    title = "🔐 <b>Connect" + (f" to {esc(d['name'])}" if d.get("name") else "") + "</b>"
    lines = [title, "", row("Host", "host"), row("Port", "port"), row("User", "user")]
    if d.get("key"):
        lines.append(f"🔑 Key: <code>{esc(d['key'])}</code>")
    elif step == "password":
        lines.append("🔑 <b>Password</b>: <i>type it below — deleted instantly</i>")
    else:
        lines.append("▫️ Password")
    if d.get("jump"):
        lines.append(f"↪️ via <code>{esc(d['jump'])}</code>")
    if error:
        lines += ["", f"⚠️ {esc(error)}"]
    if step == "host":
        lines += ["", "<i>Tip: paste user:pass@host:port here to fill everything at once.</i>"]
    rows = []
    if step == "port":
        rows.append([B("22 (default)", "port22")])
    rows.append([B("✖ Cancel", "cancel")])
    return "\n".join(lines), InlineKeyboardMarkup(rows)


async def wizard(ctx, chat, uid, d, error=None, password=None):
    """Show the next wizard step, or connect once everything is known."""
    if d.get("host") and d.get("port") and d.get("user"):
        apply_saved(d)
    step = next_step(d)
    if step is None or (step == "password" and password):
        await do_connect(ctx, chat, uid, d, password)
        return
    ctx.chat_data["draft"], ctx.chat_data["step"] = d, step
    await panel(ctx, chat, "wiz", *wizard_view(d, step, error))


async def do_connect(ctx, chat, uid, d, password=None):
    cfg = {k: d.get(k) for k in ("host", "port", "user", "key", "jump", "tmux", "name")}
    ctx.chat_data["step"] = None
    ctx.chat_data.pop("draft", None)
    ctx.chat_data["last"] = dict(cfg)
    label = sshconn.label_of(cfg)
    if cfg.get("name"):
        label = f"{cfg['name']} · {label}"
    await panel(ctx, chat, "wiz", f"⏳ Connecting to <code>{esc(label)}</code>…")

    chain = []
    try:
        chain, notes = await sshconn.connect_target(store, cfg, password)
        cols, rows = config.SIZES[config.DEFAULT_SIZE]
        args = ()
        if cfg.get("tmux"):
            t = shlex.quote(config.TMUX_SESSION)
            args = (f'command -v tmux >/dev/null 2>&1 && exec tmux new-session -A -s {t} '
                    f'|| exec "${{SHELL:-/bin/sh}}" -l',)
        proc = await chain[-1].create_process(*args, term_type="xterm-256color", term_size=(cols, rows),
                                              encoding="utf-8", errors="replace")
    except Exception as e:
        for c in chain:
            c.close()
        store.audit(uid, "connect_failed", target=label, error=type(e).__name__)
        kb = KB([B("🔁 Try again", "retry"), B("🏠 Menu", "menu")])
        await panel(ctx, chat, "wiz", f"❌ <b>Connection failed</b>\n<code>{esc(label)}</code>\n\n"
                                      f"{esc(sshconn.describe_error(e))}", kb)
        ctx.chat_data.pop("wiz", None)
        return
    finally:
        password = None

    prev = mgr.current(chat)
    s = Session(mgr, mgr.new_id(), chat, ctx.bot, chain, proc, cfg, label)
    mgr.add(s)
    if prev and prev.msg_id:
        await prev.refresh()
    store.audit(uid, "connect", sid=s.sid, target=label, auth="key" if cfg.get("key") else "password")

    lines = [f"✅ Connected <b>[{s.sid}]</b> <code>{esc(label)}</code>"] + [esc(n) for n in notes]
    rows = []
    if not cfg.get("name"):
        rows.append(B("⭐ Save host", "save"))
    if not cfg.get("key"):
        rows.append(B("🔑 Use key auth", f"ik:{s.sid}"))
    await panel(ctx, chat, "wiz", "\n".join(lines), KB(rows) if rows else None)
    ctx.chat_data.pop("wiz", None)
    await s.refresh(repost=True)


async def open_host(ctx, chat, uid, name):
    h = store["hosts"].get(name)
    if not h:
        await send(ctx.bot, chat, f"No saved host <b>{esc(name)}</b>. See /hosts.")
        return
    ctx.chat_data.pop("wiz", None)
    await wizard(ctx, chat, uid, dict(h, name=name))


def parse_opts(opts: list[str], h: dict) -> str | None:
    """Apply key=/jump=/tmux=/name= options to a host dict. Returns an error or None."""
    for o in opts:
        k, sep, v = o.partition("=")
        if not sep:
            if k == "tmux":
                h["tmux"] = True
                continue
            return f"unknown option '{o}'"
        if k == "key":
            if v in ("none", "password", ""):
                h["key"] = None
            elif v in sshconn.list_keys():
                h["key"] = v
            else:
                return f"no key named '{v}' (see /keys)"
        elif k == "jump":
            if v in ("none", ""):
                h["jump"] = None
            elif v in store["hosts"]:
                h["jump"] = v
            else:
                return f"no saved host named '{v}'"
        elif k == "tmux":
            h["tmux"] = v.lower() in ("on", "yes", "1", "true")
        elif k == "name":
            if not sshconn.NAME_RE.match(v):
                return "name: letters, digits, - and _ only"
            h["_rename"] = v
        else:
            return f"unknown option '{k}'"
    return None


# ======================================================================
# input to sessions
# ======================================================================

async def send_input(ctx, uid, s: Session, text: str, msg=None):
    hidden = bool(PASSWORD_PROMPT.search(s.cursor_line()))
    if not hidden and is_dangerous(text):
        tok = secrets.token_hex(4)
        ctx.chat_data.setdefault("pending", {})[tok] = {"kind": "sess", "sid": s.sid, "cmd": text}
        if msg:
            await try_delete(ctx.bot, s.chat_id, msg.message_id)
        await send(ctx.bot, s.chat_id,
                   f"⚠️ <b>Dangerous command</b> on <b>[{s.sid}] {esc(s.label)}</b>:\n<pre>{esc(text)}</pre>",
                   KB([B("✅ Run it", f"dz:y:{tok}"), B("✖ Cancel", f"dz:n:{tok}")]))
        return
    s.write(text.replace("\n", "\r") + "\r")
    store.audit(uid, "input", sid=s.sid, target=s.label, cmd="[hidden]" if hidden else text)
    if msg and not await try_delete(ctx.bot, s.chat_id, msg.message_id):
        await s.refresh(repost=True)


def result_block(name, code, out) -> str:
    icon = "✅" if code == 0 else ("⚠️" if code is not None else "❌")
    status = f"exit {code}" if code is not None else "failed"
    out = (out or "").strip() or "(no output)"
    if len(out) > 1200:
        out = "…" + out[-1200:]
    return f"{icon} <b>{esc(name)}</b> · {status}\n<pre>{esc(out)}</pre>"


async def send_blocks(bot, chat, header, blocks):
    buf = header
    for b in blocks:
        if len(buf) + len(b) + 2 > 3900:
            await send(bot, chat, buf)
            buf = ""
        buf += ("\n\n" if buf else "") + b
    if buf:
        await send(bot, chat, buf)


async def run_all(ctx, uid, chat, cmd):
    ss = mgr.for_chat(chat)
    if not ss:
        await send(ctx.bot, chat, "No open sessions. Use /run for saved hosts.")
        return
    note = await send(ctx.bot, chat, f"⏳ Running on {len(ss)} session(s)…")

    async def one(s):
        try:
            r = await asyncio.wait_for(s.conn.run(cmd, check=False), 30)
            return result_block(f"[{s.sid}] {s.label}", r.exit_status, (r.stdout or "") + (r.stderr or ""))
        except Exception as e:
            return result_block(f"[{s.sid}] {s.label}", None, sshconn.describe_error(e))

    blocks = await asyncio.gather(*(one(s) for s in ss))
    store.audit(uid, "broadcast", cmd=cmd, targets=[s.sid for s in ss])
    if note:
        await try_delete(ctx.bot, chat, note.message_id)
    await send_blocks(ctx.bot, chat, f"📣 <code>{esc(cmd)}</code>", blocks)


async def run_hosts(ctx, uid, chat, names, cmd):
    note = await send(ctx.bot, chat, f"⏳ Running on {len(names)} host(s)…")

    async def one(n):
        try:
            r = await monitor.pool.run(n, cmd, 30)
            return result_block(n, r.exit_status, (r.stdout or "") + (r.stderr or ""))
        except Exception as e:
            return result_block(n, None, str(e) if isinstance(e, ValueError) else sshconn.describe_error(e))

    blocks = await asyncio.gather(*(one(n) for n in names))
    store.audit(uid, "run", cmd=cmd, targets=names)
    if note:
        await try_delete(ctx.bot, chat, note.message_id)
    await send_blocks(ctx.bot, chat, f"📣 <code>{esc(cmd)}</code>", blocks)


async def dash(ctx, chat, kind, x):
    try:
        if kind == "s":
            s = mgr.get(chat, int(x))
            if not s:
                return "Session is closed.", None
            res = await asyncio.wait_for(s.conn.run(DASH_CMD, check=False), 20)
        else:
            open_s = next((s for s in mgr.for_chat(chat) if s.cfg.get("name") == x), None)
            if open_s:
                res = await asyncio.wait_for(open_s.conn.run(DASH_CMD, check=False), 20)
            else:
                res = await monitor.pool.run(x, DASH_CMD, 20)
        text = format_dash(res.stdout or "")
    except Exception as e:
        msg = str(e) if isinstance(e, ValueError) else sshconn.describe_error(e)
        text = f"📊 Dashboard failed: {esc(msg)}"
    return text, KB([B("🔄 Refresh", f"dr:{kind}:{x}"), B("🏠 Menu", "menu")])


# ======================================================================
# commands
# ======================================================================

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid, chat = update.effective_user.id, update.effective_chat.id
    if uid not in config.ALLOWED:
        return
    if not auth.is_unlocked(uid):
        await send(ctx.bot, chat, lock_text(uid))
        return
    auth.touch(uid)
    await send(ctx.bot, chat, *menu_view(uid, chat))


async def cmd_help(update, ctx):
    if update.effective_user.id in config.ALLOWED:
        await send(ctx.bot, update.effective_chat.id, HELP)


async def cmd_2fa(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    if uid not in config.ALLOWED:
        return
    if auth.enabled(uid):
        if not auth.is_unlocked(uid):
            await send(ctx.bot, chat, lock_text(uid))
            return
        await send(ctx.bot, chat, f"🔐 <b>Two-factor is on</b>\nUnlock lasts {config.UNLOCK_MINUTES} min after "
                                  "your last action.", KB([B("🔒 Lock now", "lock")],
                                                          [B("🔁 Reset", "2r"), B("❌ Disable", "2d")],
                                                          [B("🏠 Menu", "menu")]))
        return
    await begin_2fa_setup(ctx, chat, uid, update.effective_user)


@gated
async def cmd_lock(update, ctx):
    auth.lock(update.effective_user.id)
    await send(ctx.bot, update.effective_chat.id, "🔒 Locked. Send a code to unlock.")


@gated
async def cmd_ssh(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    tokens = list(ctx.args or [])
    ctx.chat_data.pop("wiz", None)
    if not tokens:
        await wizard(ctx, chat, uid, {})
        return
    over, rest, i = {}, [], 0
    while i < len(tokens):
        t = tokens[i]
        if t == "-J" and i + 1 < len(tokens):
            over["jump"] = tokens[i + 1]
            i += 2
            continue
        if t in ("tmux", "notmux"):
            over["tmux"] = t == "tmux"
        elif t.startswith("key="):
            over["key"] = t[4:] or None
        else:
            rest.append(t)
        i += 1
    if not rest:
        await wizard(ctx, chat, uid, {})
        return
    if over.get("key") and over["key"] not in sshconn.list_keys():
        await send(ctx.bot, chat, f"No key named <b>{esc(over['key'])}</b>. See /keys.")
        return
    if over.get("jump") and over["jump"] not in store["hosts"]:
        await send(ctx.bot, chat, f"No saved jump host <b>{esc(over['jump'])}</b>. See /hosts.")
        return

    target = rest[0]
    if target in store["hosts"]:
        await wizard(ctx, chat, uid, {**store["hosts"][target], "name": target, **over})
        return
    try:
        p = sshconn.parse_target(target)
    except ValueError as e:
        await send(ctx.bot, chat, f"⚠️ Couldn't parse that: {esc(e)}\nFormat: <code>user:pass@host:port</code>")
        return
    if p["password"]:
        await try_delete(ctx.bot, chat, update.message.message_id)
    d = {"host": p["host"], "port": p["port"] or 22, "user": p["user"], **over}
    await wizard(ctx, chat, uid, d, password=p["password"])


@gated
async def cmd_sessions(update, ctx):
    await send(ctx.bot, update.effective_chat.id, *sessions_view(update.effective_chat.id))


@gated
async def cmd_switch(update, ctx):
    chat = update.effective_chat.id
    a = cmd_arg(update).lstrip("[").rstrip("]")
    if not a.isdigit() or not await mgr.switch(chat, int(a)):
        await send(ctx.bot, chat, "Usage: /switch N — see /sessions")


@gated
async def cmd_stop(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    a = cmd_arg(update).lower()
    if a == "all":
        ss = mgr.for_chat(chat)
        for s in ss:
            s.close("stopped")
        store.audit(uid, "stop_all", count=len(ss))
        await send(ctx.bot, chat, f"🛑 Stopping {len(ss)} session(s).")
        return
    s = mgr.get(chat, int(a)) if a.isdigit() else None
    if not s:
        await send(ctx.bot, chat, "Usage: /stop N or /stop all — see /sessions")
        return
    s.close("stopped")
    store.audit(uid, "stop", sid=s.sid)


@gated
async def cmd_term(update, ctx):
    s = mgr.current(update.effective_chat.id)
    if s:
        await s.refresh(repost=True)
    else:
        await send(ctx.bot, update.effective_chat.id, "No active session. /ssh to start one.")


@gated
async def cmd_all(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    cmd = cmd_arg(update)
    if not cmd:
        await send(ctx.bot, chat, "Usage: <code>/all uptime</code> — runs on every open session.")
        return
    if is_dangerous(cmd):
        tok = secrets.token_hex(4)
        ctx.chat_data.setdefault("pending", {})[tok] = {"kind": "all", "cmd": cmd}
        await send(ctx.bot, chat, f"⚠️ <b>Dangerous command</b> on ALL open sessions:\n<pre>{esc(cmd)}</pre>",
                   KB([B("✅ Run it", f"dz:y:{tok}"), B("✖ Cancel", f"dz:n:{tok}")]))
        return
    await run_all(ctx, uid, chat, cmd)


@gated
async def cmd_run(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    parts = cmd_arg(update).split(maxsplit=1)
    if len(parts) < 2:
        await send(ctx.bot, chat, "Usage: <code>/run web1,db1 uptime</code> or <code>/run all df -h</code>\n"
                                  "(saved hosts with key auth)")
        return
    sel, cmd = parts
    if sel == "all":
        names = [n for n, h in store["hosts"].items() if h.get("key")]
    else:
        names = [n for n in sel.split(",") if n]
    missing = [n for n in names if n not in store["hosts"]]
    if missing or not names:
        await send(ctx.bot, chat, f"Unknown host(s): {esc(', '.join(missing)) or 'none selected'}. See /hosts.")
        return
    if is_dangerous(cmd):
        tok = secrets.token_hex(4)
        ctx.chat_data.setdefault("pending", {})[tok] = {"kind": "run", "names": names, "cmd": cmd}
        await send(ctx.bot, chat, f"⚠️ <b>Dangerous command</b> on {esc(', '.join(names))}:\n<pre>{esc(cmd)}</pre>",
                   KB([B("✅ Run it", f"dz:y:{tok}"), B("✖ Cancel", f"dz:n:{tok}")]))
        return
    await run_hosts(ctx, uid, chat, names, cmd)


@gated
async def cmd_dash(update, ctx):
    chat = update.effective_chat.id
    a = cmd_arg(update)
    if not a:
        s = mgr.current(chat)
        if not s:
            await send(ctx.bot, chat, "Usage: /dash <i>hostname</i> or /dash N (session), or open a session first.")
            return
        kind, x = "s", str(s.sid)
    elif a.isdigit():
        kind, x = "s", a
    else:
        kind, x = "h", a
    await send(ctx.bot, chat, *(await dash(ctx, chat, kind, x)))


@gated
async def cmd_shot(update, ctx):
    chat = update.effective_chat.id
    s = mgr.current(chat)
    if not s:
        await send(ctx.bot, chat, "No active session.")
        return
    await ctx.bot.send_photo(chat, s.screenshot(), caption=f"[{s.sid}] {s.label}")


@gated
async def cmd_get(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    path = cmd_arg(update)
    s = mgr.current(chat)
    if not s or not path:
        await send(ctx.bot, chat, "Usage: /get <i>path</i> (from the active session's server; relative = home dir)")
        return
    p = path[2:] if path.startswith("~/") else path
    try:
        async with s.conn.start_sftp_client() as sftp:
            if await sftp.isdir(p):
                await send(ctx.bot, chat, "That's a directory. Try <code>tar czf x.tgz dir</code> first.")
                return
            size = (await sftp.stat(p)).size or 0
            if size > 50 * MB:
                await send(ctx.bot, chat, f"File is {human(size)}; Telegram bots can send up to 50 MB.")
                return
            async with sftp.open(p, "rb") as fh:
                data = await fh.read()
    except Exception as e:
        await send(ctx.bot, chat, f"❌ Download failed: {esc(e)}")
        return
    store.audit(uid, "download", sid=s.sid, path=path, size=len(data))
    await ctx.bot.send_document(chat, InputFile(io.BytesIO(data), filename=os.path.basename(p) or "file"),
                                caption=f"📥 {path} ({human(len(data))}) from [{s.sid}]")


@gated
async def cmd_snippets(update, ctx):
    await send(ctx.bot, update.effective_chat.id, *snippets_view("a"))


@gated
async def cmd_snip(update, ctx):
    chat = update.effective_chat.id
    parts = cmd_arg(update).split(maxsplit=2)
    if len(parts) == 3 and parts[0] == "add":
        name, cmd = parts[1], parts[2]
        if not sshconn.NAME_RE.match(name):
            await send(ctx.bot, chat, "Snippet name: letters, digits, - and _ only.")
            return
        store["snippets"][name] = cmd
        store.save()
        await send(ctx.bot, chat, f"⚡ Saved snippet <b>{esc(name)}</b>.", snippets_view("a")[1])
    elif len(parts) == 2 and parts[0] == "del":
        ok = store["snippets"].pop(parts[1], None) is not None
        store.save()
        await send(ctx.bot, chat, "🗑 Deleted." if ok else "No such snippet.")
    else:
        await send(ctx.bot, chat, "Usage: <code>/snip add name command</code> · <code>/snip del name</code>")


@gated
async def cmd_hosts(update, ctx):
    await send(ctx.bot, update.effective_chat.id, *hosts_view())


@gated
async def cmd_host(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    a = list(ctx.args or [])
    sub = a[0] if a else ""
    hosts = store["hosts"]
    if sub == "add" and len(a) >= 3:
        name, target, opts = a[1], a[2], a[3:]
        if not sshconn.NAME_RE.match(name) or name in hosts:
            await send(ctx.bot, chat, "Pick a new name: letters, digits, - and _ only.")
            return
        try:
            p = sshconn.parse_target(target)
        except ValueError as e:
            await send(ctx.bot, chat, f"⚠️ {esc(e)}")
            return
        if p["password"]:
            await try_delete(ctx.bot, chat, update.message.message_id)
            await send(ctx.bot, chat, "Passwords are never saved. Use <code>user@host:port</code>, "
                                      "you'll be asked for the password when connecting (or use key=…).")
            return
        if not p["user"]:
            await send(ctx.bot, chat, "Include a user: <code>/host add web1 root@1.2.3.4:22</code>")
            return
        h = {"host": p["host"], "port": p["port"] or 22, "user": p["user"], "key": None, "jump": None, "tmux": False}
        err = parse_opts(opts, h)
        if err:
            await send(ctx.bot, chat, f"⚠️ {esc(err)}")
            return
        h.pop("_rename", None)
        hosts[name] = h
        store.save()
        store.audit(uid, "host_add", name=name)
        await send(ctx.bot, chat, *host_view(name))
    elif sub == "set" and len(a) >= 3 and a[1] in hosts:
        name = a[1]
        h = dict(hosts[name])
        err = parse_opts(a[2:], h)
        if err:
            await send(ctx.bot, chat, f"⚠️ {esc(err)}")
            return
        if h.get("jump") == name:
            await send(ctx.bot, chat, "A host can't be its own jump host.")
            return
        new = h.pop("_rename", None)
        if new and new != name:
            if new in hosts:
                await send(ctx.bot, chat, "That name is taken.")
                return
            del hosts[name]
            for other in hosts.values():
                if other.get("jump") == name:
                    other["jump"] = new
            name = new
        hosts[name] = h
        store.save()
        store.audit(uid, "host_set", name=name)
        await send(ctx.bot, chat, *host_view(name))
    elif sub == "del" and len(a) == 2 and a[1] in hosts:
        await send(ctx.bot, chat, f"Delete <b>{esc(a[1])}</b>?", KB([B("🗑 Yes, delete", f"hxy:{a[1]}"),
                                                                     B("✖ No", "hosts")]))
    else:
        await send(ctx.bot, chat, *hosts_view())


@gated
async def cmd_keys(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    a = list(ctx.args or [])
    if len(a) == 2 and a[0] == "gen":
        await generate_key(ctx, chat, uid, a[1])
        return
    await send(ctx.bot, chat, *keys_view())


async def generate_key(ctx, chat, uid, name):
    try:
        pub = sshconn.generate_key(name)
    except ValueError as e:
        await send(ctx.bot, chat, f"⚠️ {esc(e)}")
        return
    store.audit(uid, "key_generate", name=name)
    await send(ctx.bot, chat, f"🔑 Generated <b>{esc(name)}</b> (ed25519).\n\nPublic key:\n<pre>{esc(pub)}</pre>\n"
                              "Install it: open a password session to the server and tap <b>🔑 Use key auth</b> "
                              f"or run /installkey {esc(name)}.", KB([B("🔑 Keys", "keys")]))


async def install_key(ctx, chat, uid, s: Session, keyname: str | None):
    keys = sshconn.list_keys()
    if keyname is None:
        if len(keys) > 1:
            await send(ctx.bot, chat, f"Which key should go on <b>[{s.sid}] {esc(s.label)}</b>?",
                       KB(*[[B(f"🔑 {k}", f"ikk:{s.sid}:{k}")] for k in keys]))
            return
        if not keys:
            sshconn.generate_key("main")
            store.audit(uid, "key_generate", name="main")
            keys = ["main"]
        keyname = keys[0]
    if keyname not in keys:
        await send(ctx.bot, chat, f"No key named <b>{esc(keyname)}</b>.")
        return
    try:
        r = await asyncio.wait_for(s.conn.run(sshconn.install_key_cmd(sshconn.public_key(keyname)), check=False), 20)
        ok = r.exit_status == 0
        err = (r.stderr or r.stdout or "").strip()
    except Exception as e:
        ok, err = False, sshconn.describe_error(e)
    if not ok:
        await send(ctx.bot, chat, f"❌ Couldn't install the key: {esc(err)}")
        return
    store.audit(uid, "key_install", sid=s.sid, key=keyname, target=s.label)
    s.cfg["key"] = keyname
    last = ctx.chat_data.get("last")
    if last and (last["host"], last["port"], last["user"]) == (s.cfg["host"], s.cfg["port"], s.cfg["user"]):
        last["key"] = keyname
    name = find_saved(s.cfg)
    if name:
        store["hosts"][name]["key"] = keyname
        store.save()
        await send(ctx.bot, chat, f"✅ Key <b>{esc(keyname)}</b> installed. Saved host <b>{esc(name)}</b> now "
                                  "logs in with it: no password needed, and monitoring works.")
    else:
        await send(ctx.bot, chat, f"✅ Key <b>{esc(keyname)}</b> installed on <code>{esc(s.label)}</code>.\n"
                                  "Save the host to use it next time.", KB([B("⭐ Save host", "save")]))


@gated
async def cmd_installkey(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    s = mgr.current(chat)
    if not s:
        await send(ctx.bot, chat, "Open a session to the server first, then run /installkey.")
        return
    await install_key(ctx, chat, uid, s, cmd_arg(update) or None)


@gated
async def cmd_forget(update, ctx):
    chat = update.effective_chat.id
    pin = cmd_arg(update)
    if pin and ":" not in pin.rsplit("]", 1)[-1]:
        pin += ":22"
    pin = pin.replace("[", "").replace("]", "")
    if pin not in store["known_hosts"]:
        pins = "\n".join(f"<code>{esc(p)}</code>" for p in store["known_hosts"]) or "none"
        await send(ctx.bot, chat, f"Usage: /forget host:port\n\nPinned:\n{pins}")
        return
    await ask_code(ctx, chat, {"kind": "forget", "pin": pin}, f"Forget the pinned host key of <code>{esc(pin)}</code>?")


@gated
async def cmd_checks(update, ctx):
    await send(ctx.bot, update.effective_chat.id, *checks_view())


@gated
async def cmd_check(update, ctx):
    uid, chat = update.effective_user.id, update.effective_chat.id
    a = [x.lstrip("#") for x in (ctx.args or [])]
    sub = a[0] if a else ""
    if sub == "add":
        ctx.chat_data["ckwiz"] = {}
        ctx.chat_data.pop("ckw", None)
        await ck_types(ctx, chat)
        return
    if len(a) != 2 or a[1] not in store["checks"]:
        await send(ctx.bot, chat, "Usage: /check add · /check del|pause|resume|run <i>id</i>")
        return
    cid = a[1]
    if sub == "del":
        monitor.delete(cid)
        store.audit(uid, "check_del", id=cid)
        await send(ctx.bot, chat, f"🗑 Deleted check #{cid}.")
    elif sub in ("pause", "resume"):
        monitor.set_enabled(cid, sub == "resume")
        await send(ctx.bot, chat, f"{'▶️ Resumed' if sub == 'resume' else '⏸ Paused'} check #{cid}.")
    elif sub == "run":
        await send(ctx.bot, chat, await run_check_text(cid))


async def run_check_text(cid) -> str:
    r = await monitor.run_check(cid, manual=True)
    c = store["checks"].get(cid, {})
    if r is None:
        return f"#{cid} is already running."
    ok, out = r
    return f"{'🟢' if ok else '🔴'} <code>#{cid}</code> {esc(c.get('host') or 'bot')} · {esc(c.get('title'))}\n" \
           f"<code>{esc(out)}</code>"


def parse_duration(s: str) -> int | None:
    m = re.fullmatch(r"(\d+)([mhd])", s or "")
    if not m:
        return None
    return int(m[1]) * {"m": 60, "h": 3600, "d": 86400}[m[2]]


def mute_key(target: str) -> str | None:
    t = target.lstrip("#")
    if t.isdigit() and t in store["checks"]:
        return f"check:{t}"
    if target in store["hosts"] or any(c.get("host") == target for c in store["checks"].values()):
        return f"host:{target}"
    return None


@gated
async def cmd_mute(update, ctx):
    chat = update.effective_chat.id
    a = list(ctx.args or [])
    key = mute_key(a[0]) if a else None
    dur = parse_duration(a[1]) if len(a) > 1 else 3600
    if not key or not dur:
        await send(ctx.bot, chat, "Usage: /mute <i>host</i> or /mute <i>#id</i> [30m|2h|1d] (default 1h)")
        return
    monitor.mute(key, dur)
    await send(ctx.bot, chat, f"🔕 Muted {esc(key)} for {ago(dur)}.")


@gated
async def cmd_unmute(update, ctx):
    chat = update.effective_chat.id
    a = list(ctx.args or [])
    key = mute_key(a[0]) if a else None
    if not key:
        await send(ctx.bot, chat, "Usage: /unmute <i>host</i> or /unmute <i>#id</i>")
        return
    monitor.unmute(key)
    await send(ctx.bot, chat, f"🔔 Unmuted {esc(key)}.")


@gated
async def cmd_status(update, ctx):
    await send(ctx.bot, update.effective_chat.id, monitor.status_text(len(mgr.by_id)),
               KB([B("🩺 Checks", "checks"), B("🏠 Menu", "menu")]))


@gated
async def cmd_audit(update, ctx):
    a = cmd_arg(update)
    await send(ctx.bot, update.effective_chat.id, audit_text(int(a) if a.isdigit() else 25),
               KB([B("🏠 Menu", "menu")]))


# ======================================================================
# check wizard
# ======================================================================

PARAM_PROMPTS = {
    "disk": ("Mount point and limit in %, e.g. <code>/ 90</code>", "/ 90"),
    "service": ("Service name, e.g. <code>nginx</code>", None),
    "load": ("Alert when the 5-min load exceeds CPU count × factor.\nSend the factor, e.g. <code>1.5</code>", "1.0"),
    "memory": ("Alert when available RAM drops below this %, e.g. <code>10</code>", "10"),
    "http": ("URL to check (from the bot), e.g. <code>https://example.com/health</code>", None),
    "custom": ("<code>name | command</code>\nExit code 0 = OK, anything else alerts. Output goes into the alert.", None),
}


async def ck_panel(ctx, chat, text, kb):
    await panel(ctx, chat, "ckw", "🩺 <b>New check</b>\n\n" + text, kb)


async def ck_types(ctx, chat):
    items = list(TYPES.items())
    rows = [[B(lbl, f"cat:{t}") for t, lbl in items[i:i + 3]] for i in range(0, len(items), 3)]
    rows.append([B("✖ Cancel", "ckx")])
    await ck_panel(ctx, chat, "What should I watch?", InlineKeyboardMarkup(rows))


async def ck_ask_param(ctx, chat, error=None):
    w = ctx.chat_data.get("ckwiz", {})
    prompt, default = PARAM_PROMPTS[w["type"]]
    ctx.chat_data["await"] = "ckparam"
    where = f"<b>{esc(w.get('host') or 'bot')}</b> · {TYPES[w['type']]}\n\n"
    rows = []
    if default:
        rows.append([B(f"Use default ({default})", "cad")])
    rows.append([B("⬅️ Back", "ca"), B("✖ Cancel", "ckx")])
    await ck_panel(ctx, chat, where + prompt + (f"\n\n⚠️ {esc(error)}" if error else ""), InlineKeyboardMarkup(rows))


async def ck_param(ctx, chat, text):
    w = ctx.chat_data.get("ckwiz", {})
    try:
        w["check"] = build_check(w["type"], w.get("host"), text)
    except (ValueError, KeyError) as e:
        await ck_ask_param(ctx, chat, str(e) or "invalid value")
        return
    ctx.chat_data.pop("await", None)
    c = w["check"]
    await ck_panel(ctx, chat, f"<b>{esc(c.get('host') or 'bot')}</b> · {esc(c['title'])}\n\nHow often?",
                   KB([B(f"every {k}", f"cai:{k}") for k in INTERVALS],
                      [B("⬅️ Back", "ckbp"), B("✖ Cancel", "ckx")]))


# ======================================================================
# text, documents, buttons
# ======================================================================

async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid, chat, msg = update.effective_user.id, update.effective_chat.id, update.message
    raw = msg.text or ""
    m = CODE_RE.match(raw)
    if m and (ctx.chat_data.get("await_code") or not auth.is_unlocked(uid)):
        await try_delete(ctx.bot, chat, msg.message_id)
        await handle_code(update, ctx, m[1] + m[2])
        return
    if not auth.is_unlocked(uid):
        await try_delete(ctx.bot, chat, msg.message_id)     # could be a password typed while locked
        await send(ctx.bot, chat, lock_text(uid))
        return
    auth.touch(uid)

    awaiting = ctx.chat_data.get("await")
    if awaiting:
        await try_delete(ctx.bot, chat, msg.message_id)
        text = raw.strip()
        if awaiting == "hostname":
            await save_host(ctx, chat, uid, text)
        elif awaiting == "keyname":
            ctx.chat_data.pop("await", None)
            await generate_key(ctx, chat, uid, text)
        elif awaiting == "ckparam":
            await ck_param(ctx, chat, text)
        return

    step = ctx.chat_data.get("step")
    if step:
        await try_delete(ctx.bot, chat, msg.message_id)
        d = ctx.chat_data.get("draft", {})
        text, err = raw.strip(), None
        if step == "password":
            await do_connect(ctx, chat, uid, d, raw)
            return
        if step == "host":
            try:
                p = sshconn.parse_target(text)
            except ValueError as e:
                err = str(e)
            else:
                d["host"] = p["host"]
                d["port"] = p["port"] or d.get("port") or (22 if p["user"] else None)
                d["user"] = p["user"] or d.get("user")
                if p["password"]:
                    await wizard(ctx, chat, uid, d, password=p["password"])
                    return
        elif step == "port":
            if text.isdigit() and 1 <= int(text) <= 65535:
                d["port"] = int(text)
            else:
                err = "That's not a valid port (1–65535)."
        elif step == "user":
            d["user"] = text
        await wizard(ctx, chat, uid, d, err)
        return

    s = mgr.current(chat)
    if s:
        await send_input(ctx, uid, s, raw, msg)
        return
    await send(ctx.bot, chat, "No active session.\n\n" + menu_view(uid, chat)[0], menu_view(uid, chat)[1])


async def save_host(ctx, chat, uid, name):
    last = ctx.chat_data.get("last")
    if not last:
        ctx.chat_data.pop("await", None)
        return
    if not sshconn.NAME_RE.match(name) or name in store["hosts"]:
        await send(ctx.bot, chat, "Use a new name with letters, digits, - and _ only. Try again:")
        return
    ctx.chat_data.pop("await", None)
    store["hosts"][name] = {k: last.get(k) for k in ("host", "port", "user", "key", "jump", "tmux")}
    store["hosts"][name]["tmux"] = bool(last.get("tmux"))
    store.save()
    for s in mgr.for_chat(chat):
        if find_saved(s.cfg) == name:
            s.cfg["name"] = name
    store.audit(uid, "host_add", name=name)
    await send(ctx.bot, chat, f"⭐ Saved as <b>{esc(name)}</b>. Connect any time with <code>/ssh {esc(name)}</code>.",
               KB([B(f"⚙️ {name} settings", f"hv:{name}")]))


@gated
async def on_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid, chat, msg = update.effective_user.id, update.effective_chat.id, update.message
    doc, cap = msg.document, (msg.caption or "").strip()
    if doc.file_size and doc.file_size > 20 * MB:
        await send(ctx.bot, chat, "Telegram only lets bots download files up to 20 MB.")
        return
    if cap.startswith("/importkey"):
        parts = cap.split(maxsplit=2)
        name = parts[1] if len(parts) > 1 else "imported"
        passphrase = parts[2] if len(parts) > 2 else None
        data = bytes(await (await doc.get_file()).download_as_bytearray())
        await try_delete(ctx.bot, chat, msg.message_id)
        try:
            pub = sshconn.import_key(name, data, passphrase)
        except Exception as e:
            await send(ctx.bot, chat, f"❌ Couldn't import the key: {esc(e)}\n(The message was deleted anyway.)")
            return
        store.audit(uid, "key_import", name=name)
        await send(ctx.bot, chat, f"🔑 Imported <b>{esc(name)}</b>; your message with the private key was "
                                  f"deleted.\n<pre>{esc(pub)}</pre>", KB([B("🔑 Keys", "keys")]))
        return

    s = mgr.current(chat)
    if not s:
        await send(ctx.bot, chat, "Open a session first; files you send are uploaded to that server.")
        return
    fname = os.path.basename(doc.file_name or "upload.bin")
    remote = cap or fname
    if remote in ("~", "~/"):
        remote = "."
    elif remote.startswith("~/"):
        remote = remote[2:]
    if remote.endswith("/"):
        remote += fname
    note = await send(ctx.bot, chat, f"⏳ Uploading {esc(fname)}…")
    try:
        data = bytes(await (await doc.get_file()).download_as_bytearray())
        async with s.conn.start_sftp_client() as sftp:
            if await sftp.isdir(remote):
                remote = remote.rstrip("/") + "/" + fname
            async with sftp.open(remote, "wb") as fh:
                await fh.write(data)
            full = await sftp.realpath(remote)
    except Exception as e:
        await send(ctx.bot, chat, f"❌ Upload failed: {esc(e)}")
        return
    finally:
        if note:
            await try_delete(ctx.bot, chat, note.message_id)
    store.audit(uid, "upload", sid=s.sid, path=full, size=len(data))
    await send(ctx.bot, chat, f"📤 <code>{esc(fname)}</code> → <code>{esc(full)}</code> ({human(len(data))}) "
                              f"on [{s.sid}]")


async def on_button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = q.from_user.id
    if uid not in config.ALLOWED or not q.message:
        await q.answer()
        return
    chat = q.message.chat.id
    data = q.data or ""
    if data == "cfc":
        ctx.chat_data.pop("confirm", None)
        ctx.chat_data.pop("await_code", None)
        await q.answer("Cancelled")
        await show(q, ctx, *menu_view(uid, chat))
        return
    if not auth.is_unlocked(uid):
        await q.answer("🔒 Locked — send your 6-digit code first.", show_alert=True)
        return
    auth.touch(uid)
    head, _, rest = data.partition(":")

    # ---------- terminal keys & actions ----------
    if head == "k":
        sid, _, key = rest.partition(":")
        s = mgr.get(chat, int(sid))
        if not s:
            await q.answer("Session closed")
            return
        if not s.active:
            await mgr.switch(chat, s.sid)
        s.write(KEYS[key])
        await q.answer()
        return
    if head == "t":
        sid, _, act = rest.partition(":")
        s = mgr.get_any(chat, int(sid))
        if not s:
            await q.answer("Session not found")
            return
        await q.answer()
        if act == "out":
            await ctx.bot.send_document(chat, s.output_file(), caption=f"📄 Output of [{s.sid}] {s.label}")
        elif s.closed:
            await send(ctx.bot, chat, "That session is closed.")
        elif act == "shot":
            await ctx.bot.send_photo(chat, s.screenshot(), caption=f"[{s.sid}] {s.label}")
        elif act == "dash":
            await send(ctx.bot, chat, *(await dash(ctx, chat, "s", str(s.sid))))
        elif act == "size":
            s.toggle_size()
            await s.refresh()
        elif act == "snip":
            await send(ctx.bot, chat, *snippets_view(str(s.sid)))
        elif act == "exit":
            s.close("closed by you")
            store.audit(uid, "stop", sid=s.sid)
        return

    await q.answer()

    # ---------- navigation ----------
    if data == "menu":
        ctx.chat_data["step"] = None
        await show(q, ctx, *menu_view(uid, chat))
    elif data == "help":
        await show(q, ctx, HELP, KB([B("🏠 Menu", "menu")]))
    elif data == "sessions":
        await show(q, ctx, *sessions_view(chat))
    elif data == "hosts":
        await show(q, ctx, *hosts_view())
    elif data == "keys":
        await show(q, ctx, *keys_view())
    elif data == "checks":
        await show(q, ctx, *checks_view())
    elif data == "status":
        await show(q, ctx, monitor.status_text(len(mgr.by_id)), KB([B("🩺 Checks", "checks"), B("🏠 Menu", "menu")]))
    elif data == "audit":
        await show(q, ctx, audit_text(), KB([B("🏠 Menu", "menu")]))
    elif head == "snips":
        await show(q, ctx, *snippets_view(rest or "a"))
    elif data == "lock":
        auth.lock(uid)
        await show(q, ctx, "🔒 Locked. Send a code to unlock.")
    elif data == "2r":
        await ask_code(ctx, chat, {"kind": "2fa_reset"}, "Reset two-factor (link a new authenticator)?")
    elif data == "2d":
        await ask_code(ctx, chat, {"kind": "2fa_disable"}, "Disable two-factor?")

    # ---------- sessions ----------
    elif head == "sw":
        if not await mgr.switch(chat, int(rest)):
            await send(ctx.bot, chat, "That session is closed.")
    elif head == "st":
        s = mgr.get(chat, int(rest))
        if s:
            s.close("stopped")
            store.audit(uid, "stop", sid=s.sid)
            await asyncio.sleep(0.5)
        await show(q, ctx, *sessions_view(chat))
    elif data == "stall":
        for s in mgr.for_chat(chat):
            s.close("stopped")
        store.audit(uid, "stop_all")
        await asyncio.sleep(0.5)
        await show(q, ctx, *sessions_view(chat))

    # ---------- connect wizard ----------
    elif data == "new":
        if q.message and not is_terminal_msg(q.message.message_id):
            ctx.chat_data["wiz"] = q.message.message_id
        else:
            ctx.chat_data.pop("wiz", None)
        await wizard(ctx, chat, uid, {})
    elif data == "retry":
        ctx.chat_data["wiz"] = q.message.message_id
        await wizard(ctx, chat, uid, dict(ctx.chat_data.get("last") or {}))
    elif data == "port22":
        d = ctx.chat_data.setdefault("draft", {})
        d["port"] = 22
        ctx.chat_data["wiz"] = q.message.message_id
        await wizard(ctx, chat, uid, d)
    elif data == "cancel":
        ctx.chat_data["step"] = None
        ctx.chat_data.pop("draft", None)
        await show(q, ctx, *menu_view(uid, chat))
    elif data == "save":
        last = ctx.chat_data.get("last")
        if not last:
            return
        base = re.sub(r"[^A-Za-z0-9_-]", "-", last["host"])[:24].strip("-") or "server"
        sug, n = base, 2
        while sug in store["hosts"]:
            sug, n = f"{base}-{n}", n + 1
        ctx.chat_data["await"] = "hostname"
        await send(ctx.bot, chat, f"⭐ Name for <code>{esc(sshconn.label_of(last))}</code>?\n"
                                  "Send a short name (letters, digits, - _), or tap:",
                   KB([B(f"Use “{sug}”", f"sn:{sug}")], [B("✖ Cancel", "cna")]))
    elif head == "sn":
        await save_host(ctx, chat, uid, rest)
    elif data == "cna":
        ctx.chat_data.pop("await", None)
        await show(q, ctx, *menu_view(uid, chat))

    # ---------- hosts ----------
    elif head == "hv":
        await show(q, ctx, *host_view(rest))
    elif head == "ho":
        await open_host(ctx, chat, uid, rest)
    elif head == "ha" and rest in store["hosts"]:
        opts = [None] + sshconn.list_keys()
        h = store["hosts"][rest]
        h["key"] = opts[(opts.index(h.get("key")) + 1) % len(opts)] if h.get("key") in opts else None
        store.save()
        await show(q, ctx, *host_view(rest))
    elif head == "ht" and rest in store["hosts"]:
        store["hosts"][rest]["tmux"] = not store["hosts"][rest].get("tmux")
        store.save()
        await show(q, ctx, *host_view(rest))
    elif head == "hx":
        await show(q, ctx, f"Delete <b>{esc(rest)}</b>?", KB([B("🗑 Yes, delete", f"hxy:{rest}"), B("✖ No", f"hv:{rest}")]))
    elif head == "hxy":
        if store["hosts"].pop(rest, None):
            for h in store["hosts"].values():
                if h.get("jump") == rest:
                    h["jump"] = None
            for cid in [c for c, v in store["checks"].items() if v.get("host") == rest]:
                monitor.delete(cid)
            store.save()
            monitor.pool.drop(rest)
            store.audit(uid, "host_del", name=rest)
        await show(q, ctx, *hosts_view())

    # ---------- keys ----------
    elif data == "kg":
        keys = sshconn.list_keys()
        sug = "main" if "main" not in keys else f"key{len(keys) + 1}"
        ctx.chat_data["await"] = "keyname"
        await send(ctx.bot, chat, "🔑 Name for the new key? (letters, digits, - _)",
                   KB([B(f"Use “{sug}”", f"kgn:{sug}")], [B("✖ Cancel", "cna")]))
    elif head == "kgn":
        ctx.chat_data.pop("await", None)
        await generate_key(ctx, chat, uid, rest)
    elif head == "kp":
        try:
            await send(ctx.bot, chat, f"🔑 <b>{esc(rest)}</b> public key:\n<pre>{esc(sshconn.public_key(rest))}</pre>\n"
                                      "Add it to <code>~/.ssh/authorized_keys</code>, or use /installkey in a session.")
        except FileNotFoundError:
            await send(ctx.bot, chat, "Key not found.")
    elif head == "kx":
        users = [n for n, h in store["hosts"].items() if h.get("key") == rest]
        warn = f"\n⚠️ Used by: {esc(', '.join(users))} (they'll switch to password auth)" if users else ""
        await show(q, ctx, f"Delete key <b>{esc(rest)}</b>? This can't be undone.{warn}",
                   KB([B("🗑 Yes, delete", f"kxy:{rest}"), B("✖ No", "keys")]))
    elif head == "kxy":
        sshconn.delete_key(rest)
        for h in store["hosts"].values():
            if h.get("key") == rest:
                h["key"] = None
        store.save()
        store.audit(uid, "key_delete", name=rest)
        await show(q, ctx, *keys_view())
    elif head == "ik":
        s = mgr.get(chat, int(rest))
        if s:
            await install_key(ctx, chat, uid, s, None)
    elif head == "ikk":
        sid, _, kname = rest.partition(":")
        s = mgr.get(chat, int(sid))
        if s:
            await install_key(ctx, chat, uid, s, kname)

    # ---------- snippets & dangerous-command confirmations ----------
    elif head == "sp":
        target, _, name = rest.partition(":")
        s = mgr.current(chat) if target == "a" else mgr.get(chat, int(target))
        cmd = store["snippets"].get(name)
        if not s:
            await send(ctx.bot, chat, "No open session to run it in. /ssh first.")
        elif cmd:
            if not s.active:
                await mgr.switch(chat, s.sid)
            await send_input(ctx, uid, s, cmd)
            await s.refresh(repost=True)
    elif head == "dz":
        yes, _, tok = rest.partition(":")
        p = ctx.chat_data.get("pending", {}).pop(tok, None)
        await try_delete(ctx.bot, chat, q.message.message_id)
        if not p or yes != "y":
            return
        if p["kind"] == "sess":
            s = mgr.get(chat, p["sid"])
            if s:
                s.write(p["cmd"].replace("\n", "\r") + "\r")
                store.audit(uid, "input", sid=s.sid, target=s.label, cmd=p["cmd"], confirmed=True)
                await s.refresh(repost=True)
        elif p["kind"] == "all":
            await run_all(ctx, uid, chat, p["cmd"])
        elif p["kind"] == "run":
            await run_hosts(ctx, uid, chat, p["names"], p["cmd"])

    # ---------- dashboard ----------
    elif head == "dr":
        kind, _, x = rest.partition(":")
        text, kb = await dash(ctx, chat, kind, x)
        await show(q, ctx, text, kb)

    # ---------- monitoring ----------
    elif data == "ca":
        ctx.chat_data["ckwiz"] = {}
        ctx.chat_data["ckw"] = q.message.message_id
        await ck_types(ctx, chat)
    elif head == "cat":
        w = ctx.chat_data.setdefault("ckwiz", {})
        w["type"] = rest
        ctx.chat_data["ckw"] = q.message.message_id
        if rest == "http":
            await ck_ask_param(ctx, chat)
            return
        names = [n for n, h in store["hosts"].items() if h.get("key")]
        if not names:
            await ck_panel(ctx, chat, "No saved hosts with key auth yet. Checks run unattended, so they need a key.\n"
                                      "Save a host, then use 🔑 Use key auth or /installkey.",
                           KB([B("🔑 Keys", "keys"), B("⭐ Hosts", "hosts")]))
            return
        rows = [[B(f"🖥 {n}", f"cah:{n}") for n in names[i:i + 2]] for i in range(0, len(names), 2)]
        rows.append([B("⬅️ Back", "ca"), B("✖ Cancel", "ckx")])
        await ck_panel(ctx, chat, f"{TYPES[rest]} — on which host?", InlineKeyboardMarkup(rows))
    elif head == "cah":
        ctx.chat_data.setdefault("ckwiz", {})["host"] = rest
        await ck_ask_param(ctx, chat)
    elif data == "cad":
        w = ctx.chat_data.get("ckwiz", {})
        if w.get("type"):
            await ck_param(ctx, chat, PARAM_PROMPTS[w["type"]][1] or "")
    elif data == "ckbp":
        ctx.chat_data["await"] = "ckparam"
        await ck_ask_param(ctx, chat)
    elif head == "cai":
        w = ctx.chat_data.pop("ckwiz", {})
        ctx.chat_data.pop("await", None)
        if not w.get("check"):
            return
        cid = monitor.add(w["check"], INTERVALS[rest])
        store.audit(uid, "check_add", id=cid, title=w["check"]["title"])
        await ck_panel(ctx, chat, f"⏳ Added <code>#{cid}</code>, running it once…", None)
        first = await run_check_text(cid)
        await ck_panel(ctx, chat, f"✅ Check <code>#{cid}</code> added · every {rest}\n\nFirst run:\n{first}\n\n"
                                  "<i>Alerts fire after 2 failed runs in a row, and again when it recovers.</i>",
                       KB([B("🩺 All checks", "checks"), B("➕ Another", "ca")]))
        ctx.chat_data.pop("ckw", None)
    elif data == "ckx":
        ctx.chat_data.pop("ckwiz", None)
        ctx.chat_data.pop("await", None)
        await show(q, ctx, *checks_view())
    elif data == "crall":
        for cid in list(store["checks"]):
            asyncio.create_task(monitor.run_check(cid, manual=True))
        await asyncio.sleep(3)
        await show(q, ctx, *checks_view())
    elif head == "cr":
        await send(ctx.bot, chat, await run_check_text(rest))
    elif head == "cm":
        monitor.mute(f"check:{rest}", 3600)
        await send(ctx.bot, chat, f"🔕 Muted check #{esc(rest)} for 1h.")
    elif head == "mh":
        monitor.mute(f"host:{rest}", 3600)
        await send(ctx.bot, chat, f"🔕 Muted {esc(rest)} for 1h.")


# ======================================================================
# startup
# ======================================================================

COMMANDS = [
    ("start", "Main menu"), ("ssh", "Connect: /ssh user:pass@host:port"), ("sessions", "Open sessions"),
    ("switch", "Switch session: /switch N"), ("stop", "Stop session: /stop N|all"),
    ("term", "Bring the terminal back"), ("all", "Run on every open session"),
    ("run", "Run on saved hosts"), ("snippets", "Saved commands"), ("dash", "Server dashboard"),
    ("shot", "Terminal screenshot"), ("get", "Download a file"), ("hosts", "Saved hosts"),
    ("keys", "SSH keys"), ("installkey", "Install a key on this server"), ("checks", "Monitoring checks"),
    ("status", "Monitoring overview"), ("mute", "Mute alerts"), ("unmute", "Unmute alerts"),
    ("audit", "Audit log"), ("2fa", "Two-factor settings"), ("lock", "Lock now"), ("help", "All commands"),
]


async def post_init(app: Application):
    await app.bot.set_my_commands([BotCommand(c, d) for c, d in COMMANDS])
    asyncio.create_task(mgr.idle_loop())
    asyncio.create_task(monitor.loop())
    asyncio.create_task(monitor.heartbeat_loop())


def main():
    global APP
    if not config.BOT_TOKEN:
        raise SystemExit("Set BOT_TOKEN.")
    if not config.ALLOWED:
        raise SystemExit("Set ALLOWED_USERS to your Telegram user ID(s); refusing to run open to everyone.")
    APP = Application.builder().token(config.BOT_TOKEN).post_init(post_init).build()
    allowed = filters.User(user_id=config.ALLOWED)
    handlers = {
        "start": cmd_start, "menu": cmd_start, "help": cmd_help, "2fa": cmd_2fa, "lock": cmd_lock,
        "ssh": cmd_ssh, "sessions": cmd_sessions, "switch": cmd_switch, "stop": cmd_stop, "term": cmd_term,
        "all": cmd_all, "run": cmd_run, "dash": cmd_dash, "shot": cmd_shot, "get": cmd_get,
        "snippets": cmd_snippets, "snip": cmd_snip, "hosts": cmd_hosts, "host": cmd_host, "keys": cmd_keys,
        "installkey": cmd_installkey, "forget": cmd_forget, "checks": cmd_checks, "check": cmd_check,
        "mute": cmd_mute, "unmute": cmd_unmute, "status": cmd_status, "audit": cmd_audit,
    }
    for name, fn in handlers.items():
        APP.add_handler(CommandHandler(name, fn, filters=allowed))
    APP.add_handler(MessageHandler(allowed & filters.Document.ALL, on_document))
    APP.add_handler(MessageHandler(allowed & filters.TEXT & ~filters.COMMAND, on_text))
    APP.add_handler(CallbackQueryHandler(on_button))
    log.info("Bot running; allowed users: %s", config.ALLOWED)
    APP.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
