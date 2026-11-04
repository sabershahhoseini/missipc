"""All settings, read from environment variables -- optionally pre-loaded from a config file.

Pick the file with `python bot.py --config path/to/bot.conf` (or just
`python bot.py path/to/bot.conf`), or set CONFIG_FILE=path/to/bot.conf.
Format is plain KEY=VALUE, one per line, '#' comments, values may be quoted.
Real environment variables still win over anything the file sets.
"""
import os
import sys


def _config_path() -> str:
    args = sys.argv[1:]
    if "--config" in args:
        i = args.index("--config")
        if i + 1 >= len(args):
            raise SystemExit("--config needs a path")
        return args[i + 1]
    if args and not args[0].startswith("-"):
        return args[0]
    return os.environ.get("CONFIG_FILE", "")


def _load_config_file():
    path = _config_path()
    if not path:
        return
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as e:
        raise SystemExit(f"Can't read config file {path}: {e}")
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SystemExit(f"{path}:{lineno}: expected KEY=VALUE, got: {line}")
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        os.environ.setdefault(k, v)


_load_config_file()


def _ids(name: str) -> set[int]:
    return {int(x) for x in os.environ.get(name, "").replace(" ", "").split(",") if x}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ALLOWED = _ids("ALLOWED_USERS")
ALERT_CHATS = _ids("ALERT_CHAT_IDS") or ALLOWED       # who receives monitoring alerts

DATA_DIR = os.environ.get("DATA_DIR", "data")
REQUIRE_2FA = os.environ.get("REQUIRE_2FA", "1") != "0"
UNLOCK_MINUTES = _int("UNLOCK_MINUTES", 15)           # sliding window after a correct code
MAX_CODE_TRIES = 5
CODE_LOCKOUT_MIN = 15

IDLE_TIMEOUT_MIN = _int("IDLE_TIMEOUT_MIN", 30)       # 0 disables
SIZES = {"wide": (80, 24), "narrow": (46, 22)}
DEFAULT_SIZE = os.environ.get("TERM_SIZE", "wide")
if DEFAULT_SIZE not in SIZES:
    DEFAULT_SIZE = "wide"
RENDER_INTERVAL = 1.0
LOG_LIMIT = 200_000
CONNECT_TIMEOUT = 20
TMUX_SESSION = os.environ.get("TMUX_SESSION", "tgbot")

MONITOR_TICK = 10                                     # scheduler resolution, seconds
REMIND_EVERY = _int("REMIND_EVERY_MIN", 60) * 60      # repeat alert while still failing
HEALTHCHECK_URL = os.environ.get("HEALTHCHECK_URL", "")
HEALTHCHECK_INTERVAL = _int("HEALTHCHECK_INTERVAL", 300)

FONT_PATH = os.environ.get("FONT_PATH", "")
