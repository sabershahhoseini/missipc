"""SSH plumbing: target parsing, key management, host-key pinning, jump hosts."""
import asyncio
import os
import re
import shlex

import asyncssh

import config

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class HostKeyMismatch(Exception):
    def __init__(self, pin_id: str):
        super().__init__(pin_id)
        self.pin_id = pin_id


# ---------------- parsing ----------------

def parse_target(s: str) -> dict:
    """Parse  [user[:pass]@]host[:port]  — IPv6 as [addr]:port.

    Splits credentials on the LAST '@' and user/password on the FIRST ':',
    so passwords may contain both '@' and ':'.
    """
    s = s.strip()
    if not s:
        raise ValueError("empty target")
    user = password = None
    if "@" in s:
        creds, hostpart = s.rsplit("@", 1)
        user, sep, password = creds.partition(":")
        if not user:
            raise ValueError("empty username")
        password = password if sep and password else None
    else:
        hostpart = s
    port = None
    if hostpart.startswith("["):
        end = hostpart.find("]")
        if end < 0:
            raise ValueError("missing ']' in IPv6 address")
        host, rest = hostpart[1:end], hostpart[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ValueError("bad text after ']'")
            port = rest[1:]
    elif hostpart.count(":") == 1:
        host, port = hostpart.split(":")
    else:
        host = hostpart            # hostname, IPv4, or bare IPv6 without port
    if not host or any(c.isspace() for c in host):
        raise ValueError("bad host")
    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("bad port")
        port = int(port)
    return {"host": host, "port": port, "user": user, "password": password}


def label_of(c: dict) -> str:
    h = f"[{c['host']}]" if ":" in c["host"] else c["host"]
    return f"{c['user']}@{h}:{c['port']}"


def pin_id(host: str, port: int) -> str:
    return f"{host}:{port}"


# ---------------- keys ----------------

def _kpath(name: str) -> str:
    return os.path.join(config.DATA_DIR, "keys", name)


def list_keys() -> list[str]:
    d = os.path.join(config.DATA_DIR, "keys")
    return sorted(f for f in os.listdir(d) if not f.endswith(".pub")) if os.path.isdir(d) else []


def _write_key(name: str, key):
    path = _kpath(name)
    key.write_private_key(path)
    os.chmod(path, 0o600)
    key.write_public_key(path + ".pub")


def generate_key(name: str) -> str:
    if not NAME_RE.match(name):
        raise ValueError("key name: letters, digits, - and _ only (max 32)")
    if name in list_keys():
        raise ValueError(f"key '{name}' already exists")
    key = asyncssh.generate_private_key("ssh-ed25519", comment=f"tg-ssh-bot:{name}")
    _write_key(name, key)
    return public_key(name)


def import_key(name: str, data: bytes, passphrase: str | None = None) -> str:
    if not NAME_RE.match(name):
        raise ValueError("key name: letters, digits, - and _ only (max 32)")
    key = asyncssh.import_private_key(data, passphrase)
    _write_key(name, key)
    return public_key(name)


def public_key(name: str) -> str:
    with open(_kpath(name) + ".pub") as f:
        return f.read().strip()


def delete_key(name: str):
    for p in (_kpath(name), _kpath(name) + ".pub"):
        if os.path.exists(p):
            os.remove(p)


def install_key_cmd(pub: str) -> str:
    q = shlex.quote(pub)
    return ("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "
            f"(grep -qxF {q} ~/.ssh/authorized_keys || echo {q} >> ~/.ssh/authorized_keys) && echo installed")


# ---------------- connecting ----------------

async def _open(store, c: dict, password, tunnel, keepalive: bool):
    pid = pin_id(c["host"], c["port"])
    known = store["known_hosts"].get(pid)
    if known:
        pattern = c["host"] if c["port"] == 22 else f"[{c['host']}]:{c['port']}"
        known_hosts = asyncssh.import_known_hosts(f"{pattern} {known}\n")
    else:
        known_hosts = None  # first contact: trust on first use, pinned below

    kw = dict(port=c["port"], username=c["user"], known_hosts=known_hosts,
              agent_path=None, tunnel=tunnel)
    if c.get("key"):
        kw.update(client_keys=[asyncssh.read_private_key(_kpath(c["key"]))], password=None)
    else:
        kw.update(client_keys=None, password=password)
    if keepalive:
        kw.update(keepalive_interval=30, keepalive_count_max=3)
    try:
        conn = await asyncio.wait_for(asyncssh.connect(c["host"], **kw), config.CONNECT_TIMEOUT)
    except asyncssh.HostKeyNotVerifiable as e:
        raise HostKeyMismatch(pid) from e

    new_fp = None
    if not known:
        k = conn.get_server_host_key()
        store["known_hosts"][pid] = " ".join(k.export_public_key().decode().split()[:2])
        store.save()
        new_fp = k.get_fingerprint()
    return conn, new_fp


async def connect_target(store, c: dict, password=None, keepalive=False):
    """Connect (via an optional saved jump host). Returns (conn_chain, notes)."""
    chain, notes = [], []
    try:
        tunnel = None
        if c.get("jump"):
            j = store["hosts"].get(c["jump"])
            if not j:
                raise ValueError(f"jump host '{c['jump']}' isn't saved")
            if not j.get("key"):
                raise ValueError(f"jump host '{c['jump']}' must use key auth")
            if j.get("jump"):
                raise ValueError("chained jump hosts aren't supported")
            jc, fp = await _open(store, j, None, None, keepalive)
            chain.append(jc)
            tunnel = jc
            if fp:
                notes.append(f"🆕 Pinned host key of jump {j['host']}: {fp}")
        conn, fp = await _open(store, c, password, tunnel, keepalive)
        chain.append(conn)
        if fp:
            notes.append(f"🆕 Pinned host key: {fp}")
        return chain, notes
    except BaseException:
        for x in chain:
            x.close()
        raise


def describe_error(e: Exception) -> str:
    if isinstance(e, HostKeyMismatch):
        return (f"🚨 HOST KEY CHANGED for {e.pin_id}!\n"
                "This could be a man-in-the-middle attack. Nothing was sent; the connection was aborted.\n"
                f"If you reinstalled that server on purpose, run /forget {e.pin_id}")
    if isinstance(e, asyncssh.PermissionDenied):
        return "Authentication failed (wrong user, password or key)."
    if isinstance(e, asyncio.TimeoutError):
        return "Timed out connecting."
    if isinstance(e, OSError):
        return f"Network error: {e.strerror or e}"
    return f"{type(e).__name__}: {e}"
