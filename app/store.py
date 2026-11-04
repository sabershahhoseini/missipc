"""Tiny JSON store plus append-only audit log. Everything lives in DATA_DIR."""
import json
import os
import time

from . import config

DEFAULTS = {
    "totp": {},          # uid -> {secret, enabled, last_step}
    "hosts": {},         # name -> {host, port, user, key, jump, tmux}
    "known_hosts": {},   # "host:port" -> "ssh-ed25519 AAAA..."
    "snippets": {},      # name -> command
    "checks": {},        # id -> check definition
    "next_check_id": 1,
    "mutes": {},         # "host:<name>" / "check:<id>" -> unix time until
    "claude_sessions": {},  # chat_id (str) -> Claude Code session id
}


class Store:
    def __init__(self, data_dir: str = config.DATA_DIR):
        self.dir = data_dir
        os.makedirs(os.path.join(data_dir, "keys"), mode=0o700, exist_ok=True)
        os.chmod(data_dir, 0o700)
        self.path = os.path.join(data_dir, "data.json")
        self.audit_path = os.path.join(data_dir, "audit.jsonl")
        try:
            with open(self.path) as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.data = {}
        for k, v in DEFAULTS.items():
            self.data.setdefault(k, json.loads(json.dumps(v)))

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def save(self):
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)

    # ---- audit ----
    def audit(self, uid, event: str, **fields):
        rec = {"t": int(time.time()), "uid": uid, "event": event, **fields}
        fd = os.open(self.audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def read_audit(self, n: int = 20) -> list[dict]:
        try:
            with open(self.audit_path) as f:
                lines = f.readlines()[-n:]
        except FileNotFoundError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return out
