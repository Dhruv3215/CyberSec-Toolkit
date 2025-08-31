# utils/password_strength.py
import math
import re

SPECIALS = "!@#$%^&*()-_=+[]{};:,.<>?/|"
COMMON_WORDS = {
    # minimal embedded list; for deeper checks rely on zxcvbn if installed
    "password","welcome","admin","qwerty","letmein","iloveyou","dragon","football","monkey",
    "login","abcd","abc123","summer","winter","spring","autumn","india","bharat","hacker"
}

# optional zxcvbn
try:
    from zxcvbn import zxcvbn as _z
    _ZX_OK = True
except Exception:
    _ZX_OK = False

def _charset_size(s: str) -> int:
    size = 0
    if any(c.islower() for c in s): size += 26
    if any(c.isupper() for c in s): size += 26
    if any(c.isdigit() for c in s): size += 10
    if any(c in SPECIALS for c in s): size += len(SPECIALS)
    return size

def _category(score):
    if score >= 9: return "Very Strong"
    if score >= 7: return "Strong"
    if score >= 4: return "Moderate"
    return "Weak"

def _estimate_speed(hash_algo: str, hardware: str) -> float:
    """
    Rough guesses (H/s). These are illustrative for education / reports.
    """
    ha = (hash_algo or "sha256").lower()
    hw = (hardware or "gpu-consumer").lower()
    table = {
        "cpu":        {"md5": 30_000_000, "sha1": 20_000_000, "sha256": 5_000_000, "sha512": 2_000_000, "bcrypt": 300},
        "gpu-consumer":{"md5":10_000_000_000,"sha1":3_000_000_000,"sha256":1_000_000_000,"sha512":300_000_000,"bcrypt":1500},
        "gpu-enthusiast":{"md5":25_000_000_000,"sha1":8_000_000_000,"sha256":2_500_000_000,"sha512":800_000_000,"bcrypt":3000},
    }
    return table.get(hw, table["gpu-consumer"]).get(ha, 1_000_000)

def _human_seconds(secs: float) -> str:
    if secs < 1: return "<1s"
    units = [("year",31557600),("day",86400),("hour",3600),("min",60),("sec",1)]
    parts=[]
    remain=secs
    for name, s in units:
        if remain >= s:
            qty = int(remain // s)
            parts.append(f"{qty} {name}{'' if qty==1 else 's'}")
            remain -= qty*s
        if len(parts) >= 2:
            break
    return " ".join(parts) or "1 sec"

def analyze_password(password: str, hash_algo: str = "sha256", hardware: str = "gpu-consumer") -> dict:
    if not password:
        return {"score": 0, "entropy": 0, "recommendations": ["Empty password"], "category": "Weak",
                "checklist":{"has_upper":False,"has_lower":False,"has_digit":False,"has_special":False,"len_ge_8":False,"len_ge_12":False},
                "time_to_crack":"n/a","zxcvbn_score":0,"guesses_human":"0"}

    length = len(password)
    charset_size = _charset_size(password)
    entropy = round(length * (math.log2(charset_size) if charset_size > 0 else 0), 2)

    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in SPECIALS for c in password),
    ])

    # simple base score
    score = 0
    if length >= 12: score += 3
    elif length >= 8: score += 2
    elif length >= 6: score += 1
    score += classes  # up to +4
    if entropy > 60: score += 3
    elif entropy > 40: score += 2
    elif entropy > 28: score += 1

    weakness = {"in_common_dict": False, "zxcvbn_feedback": None}
    zx_score = 0
    guesses = max(1, 2**entropy)  # fallback
    if _ZX_OK:
        try:
            res = _z(password)
            zx_score = int(res.get("score", 0))
            guesses = float(res.get("guesses", guesses))
            fb = res.get("feedback") or {}
            weakness["zxcvbn_feedback"] = {
                "warning": fb.get("warning"),
                "suggestions": fb.get("suggestions") or []
            }
            # lift score if zxcvbn thinks it's stronger/weaker
            score = max(0, min(10, int(round((zx_score/4)*10)) ))
        except Exception:
            pass

    # extra common-phrase check
    lower = password.lower()
    if any(w in lower for w in COMMON_WORDS):
        weakness["in_common_dict"] = True
        score = min(score, 4)

    # time-to-crack
    speed = _estimate_speed(hash_algo, hardware)
    ttc = _human_seconds(guesses / max(1.0, speed))

    recommendations = []
    if classes < 4:
        recommendations.append("Include uppercase, lowercase, digits and special characters")
    if length < 12:
        recommendations.append("Increase length to at least 12 (recommended)")
    if entropy < 40:
        recommendations.append("Increase randomness / avoid dictionary words and patterns")
    if weakness["in_common_dict"]:
        recommendations.append("Avoid common words/phrases that appear in leaks")
    # evergreen disclaimer
    recommendations.append("Do not reuse the same password across multiple websites")

    checklist = {
        "has_upper": any(c.isupper() for c in password),
        "has_lower": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_special": any(c in SPECIALS for c in password),
        "len_ge_8": length >= 8,
        "len_ge_12": length >= 12,
    }

    out = {
        "score": max(0, min(score, 10)),
        "category": _category(score),
        "entropy": entropy,
        "zxcvbn_score": zx_score,
        "guesses_human": f"{int(guesses):,}",
        "time_to_crack": ttc,
        "recommendations": recommendations,
        "checklist": checklist,
        "weakness": weakness
    }
    return out
