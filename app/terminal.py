"""Interactive terminal sessions: VT100 emulation, live message, screenshots."""
import asyncio
import html
import io
import logging
import os
import re
import time

import pyte
from PIL import Image, ImageDraw, ImageFont
from telegram import InlineKeyboardButton as Btn, InlineKeyboardMarkup, InputFile
from telegram.constants import ParseMode
from telegram.error import BadRequest, NetworkError, RetryAfter, TimedOut

from . import config

log = logging.getLogger("missipc.term")

KEYS = {
    "esc": "\x1b", "tab": "\t", "enter": "\r",
    "up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
    "cc": "\x03", "cd": "\x04", "cz": "\x1a", "cl": "\x0c",
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
PASSWORD_PROMPT = re.compile(r"(password|passphrase|passcode|verification code|\bpin\b)", re.I)

DANGER = [re.compile(p, re.I) for p in (
    r"\brm\s+(-\S*\s+)*-\S*[rR]",              # recursive rm
    r"\b(shutdown|reboot|poweroff|halt)\b",
    r"\binit\s+[06]\b",
    r"\bmkfs(\.\w+)?\b", r"\bwipefs\b",
    r"\bdd\b.*\bof=/dev/",
    r">\s*/dev/(sd|nvme|vd|xvd|hd|mmcblk)",
    r":\(\)\s*\{",                             # fork bomb
    r"\bchmod\s+-R\s+\S+\s+/(\s|$)", r"\bchown\s+-R\s+\S+\s+/(\s|$)",
    r"\bsystemctl\s+(stop|disable|mask)\s+(ssh|sshd)\b",
    r"\biptables\s+(-F|--flush|-P\s+INPUT\s+DROP)", r"\bufw\s+(enable|default\s+deny)",
    r"\bcrontab\s+-r\b", r"\bkill\s+-9\s+-1\b",
)]


def is_dangerous(cmd: str) -> bool:
    return any(p.search(cmd) for p in DANGER)


def clean(text: str) -> str:
    return CTRL.sub("", ANSI.sub("", text.replace("\r\n", "\n")))


async def tg(call):
    """Run a Telegram API call: wait out flood limits, retry transient network
    hiccups a couple times, and swallow failure rather than raise -- a UI
    update that doesn't land shouldn't take down the handler that triggered it."""
    for attempt in range(3):
        try:
            return await call()
        except RetryAfter as e:
            await asyncio.sleep(e.retry_after + 0.5)
        except (TimedOut, NetworkError) as e:
            if attempt == 2:
                log.warning("Telegram call failed after retries: %s", e)
                return None
            await asyncio.sleep(1 + attempt)
    return None


def ago(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    return f"{s // 86400}d{(s % 86400) // 3600}h"


# ---------------- screenshot ----------------

PALETTE = {
    "black": (40, 42, 54), "red": (224, 108, 117), "green": (152, 195, 121),
    "brown": (229, 192, 123), "blue": (97, 175, 239), "magenta": (198, 120, 221),
    "cyan": (86, 182, 194), "white": (200, 204, 212),
    "brightblack": (92, 99, 112), "brightred": (255, 123, 133), "brightgreen": (177, 225, 140),
    "brightbrown": (255, 214, 143), "brightblue": (130, 199, 255), "brightmagenta": (222, 150, 245),
    "brightcyan": (120, 214, 228), "brightwhite": (255, 255, 255),
}
BG = (30, 33, 39)
FG = (215, 218, 224)
FONT_CANDIDATES = [
    config.FONT_PATH,
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "C:\\Windows\\Fonts\\consola.ttf",
]
_font_cache = {}


def _font(bold: bool):
    if bold in _font_cache:
        return _font_cache[bold]
    font = None
    for p in FONT_CANDIDATES:
        if not p or not os.path.exists(p):
            continue
        bp = p.replace("Mono.ttf", "Mono-Bold.ttf").replace("Regular", "Bold") if bold else p
        try:
            font = ImageFont.truetype(bp if os.path.exists(bp) else p, 16)
            break
        except OSError:
            continue
    _font_cache[bold] = font or ImageFont.load_default()
    return _font_cache[bold]


def _color(name: str, default):
    if name == "default":
        return default
    if name in PALETTE:
        return PALETTE[name]
    if len(name) == 6:
        try:
            return tuple(int(name[i:i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            pass
    return default


def render_png(screen: pyte.Screen, title: str) -> bytes:
    font = _font(False)
    l, t, r, b = font.getbbox("M")
    cw = max(r - l, int(font.getlength("M")) if hasattr(font, "getlength") else r - l)
    ch = int((b - t) * 1.45) + 4
    pad, bar = 14, 30
    w = screen.columns * cw + pad * 2
    h = screen.lines * ch + pad * 2 + bar
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, bar], fill=(24, 26, 31))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([12 + i * 20, 10, 24 + i * 20, 22], fill=c)
    d.text((80, 8), title, fill=(150, 155, 165), font=font)
    for y in range(screen.lines):
        row = screen.buffer[y]
        for x in range(screen.columns):
            c = row[x]
            fg, bg = _color(c.fg, FG), _color(c.bg, None)
            if c.reverse:
                fg, bg = (bg or BG), fg
            if c.bold and c.fg in PALETTE and not c.fg.startswith("bright"):
                fg = PALETTE["bright" + c.fg]
            px, py = pad + x * cw, bar + pad + y * ch
            if bg:
                d.rectangle([px, py, px + cw, py + ch], fill=bg)
            if c.data.strip():
                d.text((px, py + 2), c.data, fill=fg, font=_font(c.bold))
            if c.underscore:
                d.line([px, py + ch - 2, px + cw, py + ch - 2], fill=fg)
    cx, cy = screen.cursor.x, screen.cursor.y
    if 0 <= cy < screen.lines and 0 <= cx < screen.columns:
        px, py = pad + cx * cw, bar + pad + cy * ch
        d.rectangle([px, py, px + cw, py + ch], outline=(97, 175, 239), width=2)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


# ---------------- session ----------------

class Session:
    def __init__(self, mgr, sid, chat_id, bot, chain, proc, cfg: dict, label: str):
        self.mgr, self.sid, self.chat_id, self.bot = mgr, sid, chat_id, bot
        self.chain, self.conn, self.proc = chain, chain[-1], proc
        self.cfg, self.label = cfg, label
        self.size = config.DEFAULT_SIZE
        cols, rows = config.SIZES[self.size]
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.Stream(self.screen)
        self.log = ""
        self.msg_id = None
        self.dirty = True
        self.unread = False
        self.closed = False
        self.close_reason = ""
        self.started = self.last_input = self.last_output = time.time()
        self.lock = asyncio.Lock()
        self.renderer = asyncio.create_task(self._render_loop())
        self.reader = asyncio.create_task(self._read_loop())

    @property
    def active(self) -> bool:
        return self.mgr.active.get(self.chat_id) == self.sid

    # ----- rendering -----
    def cursor_line(self) -> str:
        y, x = self.screen.cursor.y, self.screen.cursor.x
        return self.screen.display[y][:x] if 0 <= y < self.screen.lines else ""

    def render(self) -> str:
        lines = [l.rstrip() for l in self.screen.display]
        cy, cx = self.screen.cursor.y, self.screen.cursor.x
        if not self.closed and 0 <= cy < len(lines):
            l = lines[cy].ljust(cx + 1)
            lines[cy] = (l[:cx] + "█" + l[cx + 1:]).rstrip()
        while len(lines) > 1 and not lines[-1].strip():
            lines.pop()
        body = html.escape("\n".join(lines)) or " "
        cols, rows = config.SIZES[self.size]
        if self.closed:
            status = f"🔴 closed{f' ({self.close_reason})' if self.close_reason else ''}"
        else:
            status = "🟢" if self.active else "⚪ background"
        tmux = " · 🧵 tmux" if self.cfg.get("tmux") else ""
        return (f"{status} <b>[{self.sid}] {html.escape(self.label)}</b>"
                f" · <code>{cols}×{rows}</code>{tmux}\n<pre>{body}</pre>")

    def keyboard(self) -> InlineKeyboardMarkup:
        s = self.sid
        if self.closed:
            return InlineKeyboardMarkup([[Btn("📄 Output", callback_data=f"t:{s}:out"),
                                          Btn("🖥 Sessions", callback_data="sessions"),
                                          Btn("🏠 Menu", callback_data="menu")]])
        other = "🖥 Wide" if self.size == "narrow" else "📱 Narrow"
        return InlineKeyboardMarkup([
            [Btn("Esc", callback_data=f"k:{s}:esc"), Btn("Tab", callback_data=f"k:{s}:tab"),
             Btn("←", callback_data=f"k:{s}:left"), Btn("↑", callback_data=f"k:{s}:up"),
             Btn("↓", callback_data=f"k:{s}:down"), Btn("→", callback_data=f"k:{s}:right")],
            [Btn("^C", callback_data=f"k:{s}:cc"), Btn("^D", callback_data=f"k:{s}:cd"),
             Btn("^Z", callback_data=f"k:{s}:cz"), Btn("^L", callback_data=f"k:{s}:cl"),
             Btn("⏎", callback_data=f"k:{s}:enter")],
            [Btn("⚡ Snippets", callback_data=f"t:{s}:snip"), Btn("📊 Dash", callback_data=f"t:{s}:dash"),
             Btn("🖼 Shot", callback_data=f"t:{s}:shot"), Btn("📄 Log", callback_data=f"t:{s}:out")],
            [Btn(other, callback_data=f"t:{s}:size"), Btn("🖥 Sessions", callback_data="sessions"),
             Btn("🏠 Menu", callback_data="menu"), Btn("🔌 Close", callback_data=f"t:{s}:exit")],
        ])

    async def refresh(self, repost: bool = False):
        async with self.lock:
            self.dirty = False
            text, kb = self.render(), self.keyboard()
            if self.msg_id and not repost:
                try:
                    await tg(lambda: self.bot.edit_message_text(
                        text, chat_id=self.chat_id, message_id=self.msg_id,
                        parse_mode=ParseMode.HTML, reply_markup=kb))
                    return
                except BadRequest as e:
                    if "not modified" in str(e).lower():
                        return
                    log.info("edit failed (%s), reposting", e)
            old = self.msg_id
            try:
                m = await tg(lambda: self.bot.send_message(
                    self.chat_id, text, parse_mode=ParseMode.HTML, reply_markup=kb))
            except Exception as e:
                log.warning("send failed: %s", e)
                return
            if m:
                self.msg_id = m.message_id
                self.unread = False
            if old and old != self.msg_id:
                try:
                    await self.bot.delete_message(self.chat_id, old)
                except Exception:
                    pass

    async def _render_loop(self):
        while not self.closed:
            await asyncio.sleep(config.RENDER_INTERVAL)
            if self.dirty and self.active:
                await self.refresh()

    # ----- I/O -----
    async def _read_loop(self):
        try:
            while True:
                data = await self.proc.stdout.read(4096)
                if not data:
                    break
                try:
                    self.stream.feed(data)
                except Exception:
                    # A malformed/unsupported escape sequence (known pyte bug
                    # with some private-marker CSI codes) must not be treated
                    # as the SSH connection dying -- drop this chunk and keep going.
                    log.warning("session %s: terminal parser rejected a byte sequence, skipping", self.sid)
                self.log = (self.log + data)[-config.LOG_LIMIT:]
                self.dirty = True
                self.last_output = time.time()
                if not self.active:
                    self.unread = True
        except Exception as e:
            log.info("session %s ended: %s", self.sid, e)
        finally:
            self.closed = True
            self.renderer.cancel()
            for c in reversed(self.chain):
                c.close()
            if self.msg_id:
                await self.refresh()
            await self.mgr.on_closed(self)

    def write(self, data: str):
        if not self.closed:
            self.proc.stdin.write(data)
            self.last_input = time.time()
            self.dirty = True

    def toggle_size(self):
        self.size = "narrow" if self.size == "wide" else "wide"
        cols, rows = config.SIZES[self.size]
        self.screen.resize(rows, cols)
        try:
            self.proc.change_terminal_size(cols, rows)
        except Exception:
            pass
        self.dirty = True

    def output_file(self) -> InputFile:
        return InputFile(io.BytesIO(clean(self.log).encode()), filename=f"session-{self.sid}.txt")

    def screenshot(self) -> bytes:
        return render_png(self.screen, f"[{self.sid}] {self.label}")

    def close(self, reason: str = ""):
        if not self.closed:
            self.close_reason = reason
            self.conn.close()


class SessionManager:
    def __init__(self):
        self.by_id: dict[int, Session] = {}
        self.active: dict[int, int] = {}       # chat -> sid
        self.closed: dict[int, Session] = {}   # recently closed, for logs
        self.next_id = 1

    def new_id(self) -> int:
        self.next_id += 1
        return self.next_id - 1

    def add(self, s: Session):
        self.by_id[s.sid] = s
        self.active[s.chat_id] = s.sid

    def for_chat(self, chat_id) -> list[Session]:
        return [s for s in self.by_id.values() if s.chat_id == chat_id]

    def get(self, chat_id, sid) -> Session | None:
        s = self.by_id.get(sid)
        return s if s and s.chat_id == chat_id else None

    def get_any(self, chat_id, sid) -> Session | None:
        s = self.by_id.get(sid) or self.closed.get(sid)
        return s if s and s.chat_id == chat_id else None

    def current(self, chat_id) -> Session | None:
        sid = self.active.get(chat_id)
        return self.by_id.get(sid) if sid else None

    async def switch(self, chat_id, sid) -> Session | None:
        s = self.get(chat_id, sid)
        if not s:
            return None
        prev = self.current(chat_id)
        self.active[chat_id] = sid
        if prev and prev is not s and prev.msg_id:
            await prev.refresh()          # mark old one as background
        await s.refresh(repost=True)
        return s

    async def on_closed(self, s: Session):
        self.by_id.pop(s.sid, None)
        self.closed[s.sid] = s
        while len(self.closed) > 20:
            self.closed.pop(next(iter(self.closed)))
        if self.active.get(s.chat_id) == s.sid:
            self.active.pop(s.chat_id, None)
            rest = self.for_chat(s.chat_id)
            if rest:
                nxt = max(rest, key=lambda x: x.last_input)
                self.active[s.chat_id] = nxt.sid
                try:
                    await s.bot.send_message(s.chat_id, f"Switched to session [{nxt.sid}] {nxt.label}")
                except Exception:
                    pass
                await nxt.refresh(repost=True)

    async def idle_loop(self):
        if config.IDLE_TIMEOUT_MIN <= 0:
            return
        while True:
            await asyncio.sleep(60)
            limit = time.time() - config.IDLE_TIMEOUT_MIN * 60
            for s in list(self.by_id.values()):
                if max(s.last_input, s.last_output) < limit:
                    s.close(f"idle {config.IDLE_TIMEOUT_MIN} min")
