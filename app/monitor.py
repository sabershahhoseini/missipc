"""Scheduled checks, alerting with anti-spam state machine, dashboard, connection pool."""
import asyncio
import html
import logging
import shlex
import time

import httpx
from telegram import InlineKeyboardButton as Btn, InlineKeyboardMarkup
from telegram.constants import ParseMode

from . import config, sshconn
from .terminal import ago, tg

log = logging.getLogger("sshbot.monitor")

TYPES = {
    "disk": "💾 Disk", "service": "⚙️ Service", "load": "🔥 Load",
    "memory": "🧠 Memory", "http": "🌐 HTTP", "custom": "🛠 Custom",
}
INTERVALS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600}


# ---------------- check definitions ----------------

def build_check(ctype: str, host: str | None, param: str) -> dict:
    """Turn a template + user parameter into a check. Raises ValueError on bad input."""
    param = param.strip()
    if ctype == "disk":
        parts = param.split()
        mount = parts[0] if parts else "/"
        thr = int(parts[1]) if len(parts) > 1 else 90
        if not 1 <= thr <= 100:
            raise ValueError("threshold must be 1–100")
        q = shlex.quote(mount)
        cmd = (f"p=$(df -P {q} | awk 'NR==2{{gsub(\"%\",\"\",$5);print $5}}'); "
               f"echo \"$p% used (limit {thr}%)\"; test \"$p\" -lt {thr}")
        return {"type": "disk", "host": host, "title": f"Disk {mount}", "cmd": cmd}
    if ctype == "service":
        if not param or not all(c.isalnum() or c in "-_.@" for c in param):
            raise ValueError("send a service name like nginx")
        return {"type": "service", "host": host, "title": f"Service {param}",
                "cmd": f"systemctl is-active {shlex.quote(param)}"}
    if ctype == "load":
        f = float(param or 1.0)
        cmd = (f"awk -v c=$(nproc) -v f={f} '{{printf \"load %s %s %s (%d cpu, limit %.1f)\\n\",$1,$2,$3,c,c*f; "
               f"exit ($2 > c*f)}}' /proc/loadavg")
        return {"type": "load", "host": host, "title": "Load", "cmd": cmd}
    if ctype == "memory":
        m = int(param or 10)
        cmd = (f"awk -v m={m} '/MemTotal/{{t=$2}} /MemAvailable/{{a=$2}} "
               f"END{{p=a*100/t; printf \"%.0f%% available (min {m}%%)\\n\",p; exit (p < m)}}' /proc/meminfo")
        return {"type": "memory", "host": host, "title": "Memory", "cmd": cmd}
    if ctype == "http":
        if not param.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return {"type": "http", "host": None, "title": f"HTTP {param}", "url": param}
    if ctype == "custom":
        name, sep, cmd = param.partition("|")
        if not sep or not cmd.strip():
            raise ValueError("format: name | command")
        return {"type": "custom", "host": host, "title": name.strip()[:40], "cmd": cmd.strip()}
    raise ValueError("unknown check type")


# ---------------- connection pool (key auth only) ----------------

class Pool:
    def __init__(self, store):
        self.store = store
        self.conns: dict[str, list] = {}
        self.locks: dict[str, asyncio.Lock] = {}

    async def get(self, name: str):
        h = self.store["hosts"].get(name)
        if not h:
            raise ValueError(f"host '{name}' isn't saved")
        if not h.get("key"):
            raise ValueError(f"'{name}' uses password auth; unattended runs need key auth (/keys)")
        async with self.locks.setdefault(name, asyncio.Lock()):
            chain = self.conns.get(name)
            if chain and not chain[-1].is_closed():
                return chain[-1]
            chain, _ = await sshconn.connect_target(self.store, h, keepalive=True)
            self.conns[name] = chain
            return chain[-1]

    def drop(self, name: str):
        for c in self.conns.pop(name, []):
            c.close()

    async def run(self, name: str, cmd: str, timeout=30):
        conn = await self.get(name)
        try:
            return await asyncio.wait_for(conn.run(cmd, check=False), timeout)
        except (asyncio.TimeoutError, OSError):
            self.drop(name)
            raise


# ---------------- dashboard ----------------

DASH_CMD = r"""
echo "H $(hostname)"
echo "O $( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -sr)"
echo "U $(cut -d' ' -f1 /proc/uptime)"
echo "L $(cut -d' ' -f1-3 /proc/loadavg)"
echo "N $(nproc)"
echo "C1 $(head -1 /proc/stat)"; sleep 0.5; echo "C2 $(head -1 /proc/stat)"
awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/{print "M",$1,$2}' /proc/meminfo
df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1{print "D",$6,$2,$3}'
"""


def _bar(pct: float, width=10) -> str:
    full = max(0, min(width, round(pct / 100 * width)))
    return "▓" * full + "░" * (width - full)


def _gb(kb: float) -> str:
    return f"{kb / 1048576:.1f}"


def format_dash(out: str) -> str:
    v = {"D": []}
    mem = {}
    for line in out.splitlines():
        tag, _, rest = line.partition(" ")
        if tag == "M":
            k, val = rest.split()
            mem[k.rstrip(":")] = int(val)
        elif tag == "D":
            v["D"].append(rest.split())
        else:
            v[tag] = rest.strip()
    lines = []
    try:
        up = float(v.get("U", 0))
        lines.append(f"⏱ up {ago(up)} · load {v.get('L', '?')} ({v.get('N', '?')} cpu)")
    except ValueError:
        pass
    try:
        a = [int(x) for x in v["C1"].split()[1:]]
        b = [int(x) for x in v["C2"].split()[1:]]
        idle = (b[3] + b[4]) - (a[3] + a[4])
        total = sum(b) - sum(a)
        cpu = 100 * (1 - idle / total) if total else 0
        lines.append(f"CPU   {_bar(cpu)} {cpu:3.0f}%")
    except (KeyError, IndexError, ValueError):
        pass
    if mem.get("MemTotal"):
        used = mem["MemTotal"] - mem.get("MemAvailable", 0)
        p = 100 * used / mem["MemTotal"]
        lines.append(f"RAM   {_bar(p)} {p:3.0f}%  {_gb(used)}/{_gb(mem['MemTotal'])} GB")
    if mem.get("SwapTotal"):
        used = mem["SwapTotal"] - mem.get("SwapFree", 0)
        p = 100 * used / mem["SwapTotal"]
        lines.append(f"Swap  {_bar(p)} {p:3.0f}%  {_gb(used)}/{_gb(mem['SwapTotal'])} GB")
    for d in v["D"][:8]:
        try:
            mount, total, used = d[0], int(d[1]), int(d[2])
            p = 100 * used / total if total else 0
            warn = " ⚠️" if p >= 90 else ""
            name = mount if len(mount) <= 5 else "…" + mount[-4:]
            lines.append(f"{name:<5} {_bar(p)} {p:3.0f}%  {_gb(used)}/{_gb(total)} GB{warn}")
        except (ValueError, IndexError):
            pass
    head = f"📊 <b>{html.escape(v.get('H', '?'))}</b> · {html.escape(v.get('O', ''))}"
    return f"{head}\n<pre>{html.escape(chr(10).join(lines))}</pre>"


# ---------------- monitor ----------------

class Monitor:
    def __init__(self, store, bot_getter):
        self.store = store
        self.pool = Pool(store)
        self.bot_getter = bot_getter
        self.state: dict[str, dict] = {}      # check id -> state
        self.hosts: dict[str, dict] = {}      # host name -> reachability state
        self.running: set[str] = set()

    @property
    def bot(self):
        return self.bot_getter()

    # ----- crud -----
    def add(self, check: dict, interval: int) -> str:
        cid = str(self.store["next_check_id"])
        self.store["next_check_id"] += 1
        check.update(id=cid, interval=interval, enabled=True, fails_needed=2)
        self.store["checks"][cid] = check
        self.store.save()
        return cid

    def delete(self, cid: str) -> bool:
        ok = self.store["checks"].pop(cid, None) is not None
        self.state.pop(cid, None)
        self.store.save()
        return ok

    def set_enabled(self, cid: str, on: bool) -> bool:
        c = self.store["checks"].get(cid)
        if not c:
            return False
        c["enabled"] = on
        self.store.save()
        return True

    # ----- mutes -----
    def mute(self, key: str, seconds: int):
        self.store["mutes"][key] = time.time() + seconds
        self.store.save()

    def unmute(self, key: str):
        self.store["mutes"].pop(key, None)
        self.store.save()

    def muted(self, check: dict | None = None, host: str | None = None) -> bool:
        now = time.time()
        m = self.store["mutes"]
        keys = []
        if check:
            keys.append(f"check:{check['id']}")
            if check.get("host"):
                keys.append(f"host:{check['host']}")
        if host:
            keys.append(f"host:{host}")
        return any(m.get(k, 0) > now for k in keys)

    # ----- running -----
    async def execute(self, check: dict) -> tuple[bool, str]:
        """Run one check. Returns (ok, output). Raises ConnectionError if host unreachable."""
        if check["type"] == "http":
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
                    t0 = time.time()
                    r = await c.get(check["url"])
                    ms = int((time.time() - t0) * 1000)
                return r.status_code < 400, f"HTTP {r.status_code} in {ms} ms"
            except httpx.HTTPError as e:
                return False, f"{type(e).__name__}: {e}"
        try:
            res = await self.pool.run(check["host"], check["cmd"])
        except ValueError:
            raise
        except Exception as e:
            raise ConnectionError(sshconn.describe_error(e)) from e
        out = ((res.stdout or "") + (res.stderr or "")).strip()[-600:]
        return res.exit_status == 0, out or f"exit {res.exit_status}"

    async def run_check(self, cid: str, manual=False) -> tuple[bool, str] | None:
        check = self.store["checks"].get(cid)
        if not check or cid in self.running:
            return None
        self.running.add(cid)
        st = self.state.setdefault(cid, {"status": "unknown", "fails": 0, "since": 0, "last_alert": 0,
                                         "last_run": 0, "output": ""})
        try:
            try:
                ok, out = await self.execute(check)
            except ValueError as e:
                ok, out = False, str(e)
            except ConnectionError as e:
                await self._host_result(check["host"], False, str(e))
                st["last_run"] = time.time()
                return False, str(e)
            if check.get("host"):
                await self._host_result(check["host"], True, "")
            st["last_run"], st["output"] = time.time(), out
            await self._transition(check, st, ok, out)
            return ok, out
        finally:
            self.running.discard(cid)

    async def _transition(self, check, st, ok, out):
        now = time.time()
        if ok:
            if st["status"] == "fail" and not self.muted(check):
                await self.alert(check, f"✅ <b>{self._where(check)}</b> · {html.escape(check['title'])}\n"
                                        f"Recovered after {ago(now - st['since'])}\n<code>{html.escape(out)}</code>")
            st.update(status="ok", fails=0)
            return
        st["fails"] += 1
        if st["fails"] == 1:
            st["since"] = now
        if st["status"] != "fail" and st["fails"] >= check.get("fails_needed", 2):
            st["status"] = "fail"
            if not self.muted(check):
                st["last_alert"] = now
                await self.alert(check, self._fail_text(check, st, out), self._alert_kb(check))
        elif st["status"] == "fail" and now - st["last_alert"] >= config.REMIND_EVERY and not self.muted(check):
            st["last_alert"] = now
            await self.alert(check, "⏰ Still failing\n" + self._fail_text(check, st, out), self._alert_kb(check))

    async def _host_result(self, host, ok, err):
        now = time.time()
        hs = self.hosts.setdefault(host, {"up": True, "fails": 0, "since": 0, "last_alert": 0})
        if ok:
            if not hs["up"] and not self.muted(host=host):
                await self.alert(None, f"✅ <b>{html.escape(host)}</b> is reachable again "
                                       f"(down {ago(now - hs['since'])})")
            hs.update(up=True, fails=0)
            return
        hs["fails"] += 1
        if hs["fails"] == 1:
            hs["since"] = now
        msg = (f"🔴 <b>{html.escape(host)}</b> unreachable\n{html.escape(err)}\n"
               f"since {time.strftime('%H:%M', time.localtime(hs['since']))}")
        kb = InlineKeyboardMarkup([[Btn("🔕 Mute 1h", callback_data=f"mh:{host}")]])
        if hs["up"] and hs["fails"] >= 2:
            hs["up"] = False
            if not self.muted(host=host):
                hs["last_alert"] = now
                await self.alert(None, msg, kb)
        elif not hs["up"] and now - hs["last_alert"] >= config.REMIND_EVERY and not self.muted(host=host):
            hs["last_alert"] = now
            await self.alert(None, "⏰ Still down\n" + msg, kb)

    def _where(self, check):
        return html.escape(check.get("host") or "bot")

    def _fail_text(self, check, st, out):
        since = time.strftime("%H:%M", time.localtime(st["since"]))
        return (f"🔴 <b>{self._where(check)}</b> · {html.escape(check['title'])}\n"
                f"<code>{html.escape(out)}</code>\nsince {since} · {st['fails']} failed runs")

    def _alert_kb(self, check):
        row = []
        if check.get("host"):
            row.append(Btn("📺 Terminal", callback_data=f"ho:{check['host']}"))
        row += [Btn("🔁 Run now", callback_data=f"cr:{check['id']}"),
                Btn("🔕 Mute 1h", callback_data=f"cm:{check['id']}")]
        return InlineKeyboardMarkup([row])

    async def alert(self, check, text, kb=None):
        for chat in config.ALERT_CHATS:
            try:
                await tg(lambda: self.bot.send_message(chat, text, parse_mode=ParseMode.HTML, reply_markup=kb))
            except Exception as e:
                log.warning("alert to %s failed: %s", chat, e)

    async def loop(self):
        while True:
            try:
                now = time.time()
                down = {h for h, s in self.hosts.items() if not s["up"]}
                probed = set()
                for cid, c in list(self.store["checks"].items()):
                    if not c.get("enabled", True) or cid in self.running:
                        continue
                    st = self.state.get(cid, {})
                    if now - st.get("last_run", 0) < c["interval"]:
                        continue
                    host = c.get("host")
                    if host in down:            # one probe per down host per tick, skip the rest
                        if host in probed:
                            continue
                        probed.add(host)
                    asyncio.create_task(self.run_check(cid))
            except Exception:
                log.exception("monitor tick failed")
            await asyncio.sleep(config.MONITOR_TICK)

    async def heartbeat_loop(self):
        if not config.HEALTHCHECK_URL:
            return
        async with httpx.AsyncClient(timeout=10) as c:
            while True:
                try:
                    await c.get(config.HEALTHCHECK_URL)
                except httpx.HTTPError as e:
                    log.warning("heartbeat failed: %s", e)
                await asyncio.sleep(config.HEALTHCHECK_INTERVAL)

    # ----- views -----
    def status_icon(self, cid) -> str:
        c = self.store["checks"][cid]
        if not c.get("enabled", True):
            return "⏸"
        st = self.state.get(cid, {}).get("status", "unknown")
        if c.get("host") and not self.hosts.get(c["host"], {}).get("up", True):
            return "⚫"
        return {"ok": "🟢", "fail": "🔴"}.get(st, "⚪")

    def checks_text(self) -> str:
        checks = self.store["checks"]
        if not checks:
            return "🩺 <b>Checks</b>\n\nNo checks yet. Tap ➕ Add check."
        lines = ["🩺 <b>Checks</b>", ""]
        for cid, c in checks.items():
            st = self.state.get(cid, {})
            last = f" · {ago(time.time() - st['last_run'])} ago" if st.get("last_run") else ""
            muted = " 🔕" if self.muted(c) else ""
            out = f"\n     <i>{html.escape(st['output'][:80])}</i>" if st.get("output") else ""
            lines.append(f"{self.status_icon(cid)} <code>#{cid}</code> <b>{self._where(c)}</b> · "
                         f"{html.escape(c['title'])} · every {ago(c['interval'])}{last}{muted}{out}")
        lines += ["", "🟢 ok  🔴 failing  ⚫ host down  ⚪ not run yet  ⏸ paused",
                  "/check del|pause|resume|run &lt;id&gt;"]
        return "\n".join(lines)

    def status_text(self, open_sessions: int) -> str:
        hosts = {}
        for cid, c in self.store["checks"].items():
            hosts.setdefault(c.get("host") or "bot (HTTP)", []).append(cid)
        lines = ["📋 <b>Status</b>", ""]
        if not hosts:
            lines.append("No checks configured. /checks to add some.")
        for h, cids in hosts.items():
            if h in self.hosts and not self.hosts[h]["up"]:
                lines.append(f"⚫ <b>{html.escape(h)}</b> unreachable for "
                             f"{ago(time.time() - self.hosts[h]['since'])}")
                continue
            bad = [self.store["checks"][c]["title"] for c in cids if self.status_icon(c) == "🔴"]
            muted = " 🔕" if self.muted(host=h) else ""
            if bad:
                lines.append(f"🔴 <b>{html.escape(h)}</b>{muted} · " + html.escape(", ".join(bad)))
            else:
                lines.append(f"🟢 <b>{html.escape(h)}</b>{muted} · {len(cids)} checks ok")
        active_mutes = [k for k, t in self.store["mutes"].items() if t > time.time()]
        if active_mutes:
            lines += ["", "🔕 Muted: " + ", ".join(html.escape(k) for k in active_mutes)]
        lines += ["", f"🖥 Open sessions: {open_sessions}"]
        return "\n".join(lines)
