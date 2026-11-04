"""All settings. Env vars always win; below that, an optional nested YAML file.

Pick the file with `python bot.py --config path/to/bot.yaml` (or a bare path
argument, or CONFIG_FILE=path/to/bot.yaml). Shape:

    bot:
      token: "123456:ABC..."
      allowed_users: [11111111]
      alert_chat_ids: []            # defaults to allowed_users

    security:
      require_2fa: true
      unlock_minutes: 15

    sessions:
      idle_timeout_min: 30
      term_size: wide
      tmux_session: missipc

    monitoring:
      remind_every_min: 60
      healthcheck_url: ""
      healthcheck_interval: 300

    claude:
      bin: claude
      timeout_sec: 120

    data_dir: data
    font_path: ""

See deploy/bot.yaml.example for the full, commented version.
"""
import os
import sys

import yaml


def _config_path() -> str:
    args = sys.argv[1:]
    flag = next((a for a in args if a in ("--config", "-config")), None)
    if flag:
        i = args.index(flag)
        if i + 1 >= len(args):
            raise SystemExit(f"{flag} needs a path")
        return args[i + 1]
    if args and args[0].startswith("-"):
        raise SystemExit(f"Unrecognized option '{args[0]}' -- use --config <path>")
    if args:
        return args[0]
    return os.environ.get("CONFIG_FILE", "")


def _load_yaml() -> dict:
    path = _config_path()
    if not path:
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except OSError as e:
        raise SystemExit(f"Can't read config file {path}: {e}")
    except yaml.YAMLError as e:
        raise SystemExit(f"Invalid YAML in {path}: {e}")
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: expected a mapping at the top level")
    return data


_FILE = _load_yaml()


def _path(dotted: str):
    """Walk a dotted path (e.g. 'bot.token') through the loaded YAML."""
    node = _FILE
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _str(env_name: str, dotted: str, default: str = "") -> str:
    if env_name in os.environ:
        return os.environ[env_name]
    v = _path(dotted)
    return default if v is None else str(v)


def _bool(env_name: str, dotted: str, default: bool) -> bool:
    if env_name in os.environ:
        return os.environ[env_name] != "0"
    v = _path(dotted)
    return default if v is None else bool(v)


def _int(env_name: str, dotted: str, default: int) -> int:
    v = os.environ.get(env_name)
    if v is None:
        v = _path(dotted)
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _ids(env_name: str, dotted: str) -> set[int]:
    v = os.environ.get(env_name)
    if v is None:
        v = _path(dotted)
    if v is None:
        return set()
    items = v if isinstance(v, (list, tuple)) else str(v).replace(" ", "").split(",")
    return {int(x) for x in items if str(x)}


BOT_TOKEN = _str("BOT_TOKEN", "bot.token")
ALLOWED = _ids("ALLOWED_USERS", "bot.allowed_users")
ALERT_CHATS = _ids("ALERT_CHAT_IDS", "bot.alert_chat_ids") or ALLOWED  # who receives monitoring alerts

DATA_DIR = _str("DATA_DIR", "data_dir", "data")
REQUIRE_2FA = _bool("REQUIRE_2FA", "security.require_2fa", True)
UNLOCK_MINUTES = _int("UNLOCK_MINUTES", "security.unlock_minutes", 15)  # sliding window after a correct code
MAX_CODE_TRIES = 5
CODE_LOCKOUT_MIN = 15

IDLE_TIMEOUT_MIN = _int("IDLE_TIMEOUT_MIN", "sessions.idle_timeout_min", 30)  # 0 disables
SIZES = {"wide": (80, 24), "narrow": (46, 22)}
DEFAULT_SIZE = _str("TERM_SIZE", "sessions.term_size", "wide")
if DEFAULT_SIZE not in SIZES:
    DEFAULT_SIZE = "wide"
RENDER_INTERVAL = 1.0
LOG_LIMIT = 200_000
CONNECT_TIMEOUT = 20
TMUX_SESSION = _str("TMUX_SESSION", "sessions.tmux_session", "missipc")

MONITOR_TICK = 10  # scheduler resolution, seconds
REMIND_EVERY = _int("REMIND_EVERY_MIN", "monitoring.remind_every_min", 60) * 60  # repeat while still failing
HEALTHCHECK_URL = _str("HEALTHCHECK_URL", "monitoring.healthcheck_url", "")
HEALTHCHECK_INTERVAL = _int("HEALTHCHECK_INTERVAL", "monitoring.healthcheck_interval", 300)

FONT_PATH = _str("FONT_PATH", "font_path", "")

CLAUDE_BIN = _str("CLAUDE_BIN", "claude.bin", "claude")
CLAUDE_TIMEOUT = _int("CLAUDE_TIMEOUT_SEC", "claude.timeout_sec", 120)
