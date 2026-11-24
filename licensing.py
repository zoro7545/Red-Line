"""
Red Line - licensing helpers
----------------------------
Shared by the main app (game_cafe_manager.py) and the key generator
(license_keygen.py).  Keep this file next to game_cafe_manager.py.

How it works
  * A product key is a short signed record (serial no., expiry date and the
    customer's computer) written in Base32.  It is signed with a PRIVATE key that
    only you own (it lives in the key generator's folder and is never shipped).
  * The app only contains the matching PUBLIC key, so it can CHECK a key but
    nobody can make a new one from the app's files.
  * A key made for one computer will not activate on another computer.

The signature code is a small pure-Python Ed25519 (RFC 8032) so there is nothing
extra to install.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import urllib.request
import uuid

# ---------------------------------------------------------------------------
# settings you may edit
# ---------------------------------------------------------------------------
# Public half of YOUR signing key (the keygen shows it and warns if it differs).
PUBLIC_KEY_HEX = "9ffbe9441d77ef63d02e0340866b7dab7b5ed715ade1252fd9aa1a1058b29093"
# Shown on the activation screen, e.g. "WhatsApp +91 98765 43210".
SUPPORT_CONTACT = ""
# Where your revocation list (revoked.json from the keygen) is uploaded, e.g. a GitHub
# "raw" link or your website.  Leave "" to switch the remote check off.
REVOCATION_URL = "https://raw.githubusercontent.com/zoro7545/redline_license/refs/heads/main/revoked.json"
# If the list cannot be reached (no internet) the app keeps working for this many days
# since the last successful check, then asks the customer to connect to the internet.
OFFLINE_GRACE_DAYS = 30

_PRODUCT = b"RedLineGameCafe|v1|"
_EPOCH = dt.date(2020, 1, 1)
_VERSION = 1
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_FIX = str.maketrans({"0": "O", "1": "I", "8": "B"})   # forgive look-alike typing


class LicenseError(Exception):
    """Raised with a message that is safe to show to the customer."""


class LicenseInfo:
    def __init__(self, serial, expires, machine):
        self.serial = serial          # int
        self.expires = expires        # datetime.date or None (= lifetime)
        self.machine = machine        # 10 bytes or None (= any computer)

    @property
    def lifetime(self):
        return self.expires is None

    @property
    def bound(self):
        return self.machine is not None

    def days_left(self):
        return None if self.expires is None else (self.expires - dt.date.today()).days


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032, pure Python)
# ---------------------------------------------------------------------------
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(s):
    return hashlib.sha512(s).digest()


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _h_modq(s):
    return int.from_bytes(_sha512(s), "little") % _Q


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    D = 2 * P[2] * Q[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return ((P[0] * Q[2] - Q[0] * P[2]) % _P == 0 and
            (P[1] * Q[2] - Q[1] * P[2]) % _P == 0)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(P):
    zinv = _inv(P[2])
    x, y = P[0] * zinv % _P, P[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _expand(secret):
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_from_seed(seed):
    """32-byte private seed -> 32-byte public key."""
    a, _ = _expand(seed)
    return _compress(_mul(a, _G))


def sign(seed, msg):
    a, prefix = _expand(seed)
    A = _compress(_mul(a, _G))
    r = _h_modq(prefix + msg)
    Rs = _compress(_mul(r, _G))
    h = _h_modq(Rs + A + msg)
    return Rs + int.to_bytes((r + h * a) % _Q, 32, "little")


def verify(public, msg, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = _h_modq(signature[:32] + public + msg)
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


# ---------------------------------------------------------------------------
# this computer's code
# ---------------------------------------------------------------------------
def _raw_machine_id():
    try:
        if sys.platform.startswith("win"):
            import winreg
            flags = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                0, flags) as k:
                return str(winreg.QueryValueEx(k, "MachineGuid")[0])
        if sys.platform == "darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(path):
                with open(path) as fh:
                    return fh.read().strip()
    except Exception:
        pass
    return str(uuid.getnode())


def _b32(raw):
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _unb32(text):
    text = _clean(text)
    return base64.b32decode(text + "=" * (-len(text) % 8))


def _clean(text):
    return "".join(ch for ch in str(text).upper().translate(_FIX) if ch in _ALPHABET)


def _group(text, n):
    return "-".join(text[i:i + n] for i in range(0, len(text), n))


def machine_bytes():
    return hashlib.sha256(_PRODUCT + _raw_machine_id().encode("utf-8")).digest()[:10]


def machine_code():
    """What the customer reads out / sends to you, e.g. ABCD-EFGH-JKLM-NPQR."""
    return _group(_b32(machine_bytes()), 4)


def parse_machine_code(text):
    """Machine code typed by a customer -> 10 bytes (raises LicenseError if malformed)."""
    clean = _clean(text)
    if len(clean) != 16:
        raise LicenseError("A machine code has 16 letters/digits, e.g. ABCD-EFGH-JKLM-NPQR.")
    return _unb32(clean)


# ---------------------------------------------------------------------------
# product keys
# ---------------------------------------------------------------------------
def make_key(seed, serial, expires=None, machine=None):
    """Create a product key (used by the key generator only).

    expires: datetime.date or None for lifetime.
    machine: 10 bytes (from parse_machine_code) or None to allow any computer.
    """
    days = 0
    if expires is not None:
        days = (expires - _EPOCH).days
        if not 1 <= days <= 65535:
            raise ValueError("Expiry date out of range (2020-2199).")
    if not 0 < serial < 2 ** 32:
        raise ValueError("Bad serial number.")
    payload = struct.pack(">BIH", _VERSION, serial, days) + (machine or bytes(10))
    sig = sign(seed, _PRODUCT + payload)
    return _group(_b32(payload + sig), 5)


def inspect_key(text):
    """Check the signature only and return LicenseInfo (no expiry / computer check)."""
    try:
        raw = _unb32(text)
    except Exception:
        raise LicenseError("That product key is not valid.")
    if len(raw) != 81:
        raise LicenseError("That product key is not valid (wrong length).")
    payload, sig = raw[:17], raw[17:]
    if not verify(bytes.fromhex(PUBLIC_KEY_HEX), _PRODUCT + payload, sig):
        raise LicenseError("That product key is not valid.")
    version, serial, days = struct.unpack(">BIH", payload[:7])
    if version != _VERSION:
        raise LicenseError("That product key is for a different version of the software.")
    machine = payload[7:]
    return LicenseInfo(serial,
                       None if days == 0 else _EPOCH + dt.timedelta(days=days),
                       None if machine == bytes(10) else machine)


def check_key(text):
    """Full check used at start-up: signature, expiry and this computer."""
    info = inspect_key(text)
    if info.expires is not None and dt.date.today() > info.expires:
        raise LicenseError(f"This license expired on {info.expires:%d %b %Y}.")
    if info.machine is not None and info.machine != machine_bytes():
        raise LicenseError("This product key was issued for a different computer.")
    return info


# ---------------------------------------------------------------------------
# revoking ("deleting") keys
# ---------------------------------------------------------------------------
def make_revocation_list(seed, serials):
    """Signed list of revoked serial numbers (used by the keygen) -> JSON text."""
    serials = sorted({int(x) for x in serials})
    updated = dt.date.today().isoformat()
    sig = sign(seed, _revocation_message(updated, serials))
    return json.dumps({"v": 1, "updated": updated, "revoked": serials, "sig": sig.hex()}, indent=1)


def _revocation_message(updated, serials):
    return _PRODUCT + b"REVOKED|" + updated.encode() + b"|" + ",".join(str(x) for x in serials).encode()


def parse_revocation_list(text):
    """Verify the signature and return the set of revoked serials (raises ValueError if bad)."""
    data = json.loads(text)
    serials = sorted({int(x) for x in data["revoked"]})
    if not verify(bytes.fromhex(PUBLIC_KEY_HEX), _revocation_message(str(data["updated"]), serials),
                  bytes.fromhex(data["sig"])):
        raise ValueError("bad signature")
    return set(serials)


def _fetch_revoked():
    url = REVOCATION_URL + ("&" if "?" in REVOCATION_URL else "?") + "_=" + str(int(time.time()))
    req = urllib.request.Request(url, headers={"User-Agent": "RedLine-License"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return parse_revocation_list(resp.read(500000).decode("utf-8"))


def check_revocation(info, state_path):
    """Raise LicenseError if this key was deleted by you, or if it has not been able to
    check the list for longer than OFFLINE_GRACE_DAYS.  Never raises anything else."""
    if not REVOCATION_URL:
        return
    today = dt.date.today()
    try:
        revoked = _fetch_revoked()
    except Exception:
        revoked = None                                  # offline / list missing / not genuine
    if revoked is not None:
        if info.serial in revoked:
            raise LicenseError("This product key has been deactivated."
                               + (f" Please contact {SUPPORT_CONTACT}." if SUPPORT_CONTACT else ""))
        _save_state(state_path, today)
        return
    last = _load_state(state_path)
    if last is None:                                    # first run: start the grace period now
        _save_state(state_path, today)
        return
    if (today - last).days > OFFLINE_GRACE_DAYS:
        raise LicenseError("Please connect this computer to the internet to verify your license "
                           "(last verified " + last.strftime("%d %b %Y") + ").")


def _load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return dt.date.fromisoformat(json.load(fh)["last_ok"])
    except Exception:
        return None


def _save_state(path, day):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"last_ok": day.isoformat()}, fh)
    except Exception:
        pass
