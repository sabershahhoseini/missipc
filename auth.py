"""TOTP second factor (Google Authenticator / Aegis / etc.) and the lock window."""
import hmac
import time

import pyotp

import config


class Auth:
    def __init__(self, store):
        self.store = store
        self.unlocked_until: dict[int, float] = {}
        self.fails: dict[int, list] = {}           # uid -> [count, lockout_until]

    def _rec(self, uid):
        return self.store["totp"].get(str(uid))

    def enabled(self, uid) -> bool:
        r = self._rec(uid)
        return bool(r and r.get("enabled"))

    # ---- setup ----
    def begin_setup(self, uid, account: str) -> tuple[str, str]:
        secret = pyotp.random_base32()
        self.store["totp"][str(uid)] = {"secret": secret, "enabled": False, "last_step": 0}
        self.store.save()
        uri = pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name="SSH Bot")
        return secret, uri

    def disable(self, uid):
        self.store["totp"].pop(str(uid), None)
        self.store.save()
        self.lock(uid)

    # ---- verification ----
    def verify(self, uid, code: str) -> tuple[bool, str]:
        now = time.time()
        f = self.fails.setdefault(uid, [0, 0])
        if now < f[1]:
            return False, f"Too many wrong codes. Try again in {int((f[1] - now) // 60) + 1} min."
        r = self._rec(uid)
        if not r:
            return False, "2FA isn't set up. Send /2fa."
        code = code.strip().replace(" ", "")
        totp = pyotp.TOTP(r["secret"])
        step_now = int(now // 30)
        for step in (step_now - 1, step_now, step_now + 1):      # allow small clock drift
            if hmac.compare_digest(totp.at(step * 30), code):
                if step <= r.get("last_step", 0):
                    return False, "That code was already used. Wait for the next one."
                r["last_step"] = step
                if not r.get("enabled"):
                    r["enabled"] = True
                self.store.save()
                self.fails[uid] = [0, 0]
                return True, ""
        f[0] += 1
        if f[0] >= config.MAX_CODE_TRIES:
            f[:] = [0, now + config.CODE_LOCKOUT_MIN * 60]
            return False, f"Wrong code. Locked out for {config.CODE_LOCKOUT_MIN} min."
        return False, f"Wrong code ({config.MAX_CODE_TRIES - f[0]} tries left)."

    # ---- lock window ----
    def unlock(self, uid):
        self.unlocked_until[uid] = time.time() + config.UNLOCK_MINUTES * 60

    def lock(self, uid):
        self.unlocked_until.pop(uid, None)

    def is_unlocked(self, uid) -> bool:
        if not self.enabled(uid):
            return not config.REQUIRE_2FA
        return time.time() < self.unlocked_until.get(uid, 0)

    def touch(self, uid):
        """Slide the unlock window forward on activity."""
        if self.enabled(uid) and self.is_unlocked(uid):
            self.unlock(uid)
