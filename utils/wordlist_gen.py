# utils/wordlist_gen.py
import random
import string

SPECIALS = "!@#$%^&*()-_=+[]{};:,.<>?/|"
LEET_MAP = {"a":"@", "A":"@", "e":"3", "E":"3", "i":"1", "I":"1", "o":"0", "O":"0", "s":"$", "S":"$"}

POLICIES = {
    "default": {"name":"Strong (default)", "min_len":12, "max_len":128, "require_classes":4},
    "nist":    {"name":"NIST SP 800-63B", "min_len":8,  "max_len":128, "require_classes":0},  # no forced complexity
    "pci":     {"name":"PCI DSS v4.0",    "min_len":12, "max_len":64,  "require_classes":3},
    "company": {"name":"Company Policy",  "min_len":14, "max_len":128, "require_classes":4},
}

def get_policy_by_name(name: str):
    key = (name or "default").lower()
    if key in POLICIES: return POLICIES[key]
    # friendly aliases
    if key in ("nist sp 800-63b", "nist-63b"): return POLICIES["nist"]
    if key in ("pci", "pci-dss", "pci dss"): return POLICIES["pci"]
    if key in ("company", "custom"): return POLICIES["company"]
    return POLICIES["default"]

def apply_leet(token: str) -> str:
    return "".join(LEET_MAP.get(c, c) for c in token)

def rotate_token(token: str, n: int = 1) -> str:
    if not token:
        return token
    n = n % len(token)
    return token[n:] + token[:n]

def ensure_requirements(candidate: str, min_len: int, policy=None) -> str:
    policy = policy or POLICIES["default"]
    req_classes = policy.get("require_classes", 4)

    has_upper = any(c.isupper() for c in candidate)
    has_lower = any(c.islower() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    has_special = any(c in SPECIALS for c in candidate)

    # pad to min_len first
    if len(candidate) < min_len:
        pool = string.ascii_letters + string.digits + SPECIALS
        while len(candidate) < min_len:
            candidate += random.choice(pool)

    # enforce classes if policy requires it
    if req_classes >= 1 and not has_upper:
        candidate += random.choice(string.ascii_uppercase); has_upper=True
    if req_classes >= 2 and not has_lower:
        candidate += random.choice(string.ascii_lowercase); has_lower=True
    if req_classes >= 3 and not has_digit:
        candidate += random.choice(string.digits); has_digit=True
    if req_classes >= 4 and not has_special:
        candidate += random.choice(SPECIALS); has_special=True

    # shuffle final
    candidate = ''.join(random.sample(candidate, len(candidate)))
    return candidate

def _year_variants():
    # simple pool of common year suffixes
    cur = 2025
    base = list(range(1990, cur+1))
    return [str(y) for y in base]

YEARS = _year_variants()

def generate_password(inputs: dict, min_len: int, max_len: int, method: str = "all", policy=None) -> str:
    """
    Deterministic-ish generation using provided seeds and transformations.
    Always returns a string that, after ensure_requirements, meets needed char classes per policy.
    """
    policy = policy or POLICIES["default"]

    # gather tokens  
    tokens = []
    for k in ["name","pet","hobbies","dob","crush","random","custom"]:
        v = inputs.get(k)
        if not v:
            continue
        s = str(v)
        if "," in s:
            parts = [p.strip() for p in s.split(",") if p.strip()]
            tokens.extend(parts)
        else:
            tokens.append(s.strip())
    if not tokens:
        tokens = ["seed"]

    base = random.choice(tokens)

    # apply transform  
    if method == "reverse":
        candidate = base[::-1]
    elif method == "mixed":
        candidate = ''.join(random.sample(base, len(base)))
    elif method == "leet":
        candidate = apply_leet(base)
    elif method == "rotate":
        candidate = rotate_token(base, random.randint(1, max(1, len(base))))
    elif method == "combine":
        candidate = base + random.choice(tokens)
    elif method == "all":
        candidate = base
        if random.random() < 0.45:
            candidate = apply_leet(candidate)
        if random.random() < 0.45:
            candidate = rotate_token(candidate, random.randint(1, max(1, len(candidate))))
        if random.random() < 0.35:
            candidate = candidate[::-1]
        if random.random() < 0.4:
            candidate += random.choice(tokens)
    else:
        candidate = base

    # random numerical / specials (include year patterns)
    if random.random() < 0.6:
        candidate += random.choice(YEARS)
    elif random.random() < 0.7:
        candidate += str(random.randint(0, 9999))
    if random.random() < 0.5:
        candidate += random.choice(SPECIALS)
    if random.random() < 0.4:
        candidate = random.choice(SPECIALS) + candidate

    # enforce max length
    if len(candidate) > max_len:
        candidate = candidate[:max_len]

    return ensure_requirements(candidate, min_len, policy=policy)

def generate_passwords(inputs: dict, min_len: int, max_len: int, count: int = 1, method: str = "all", policy=None):
    out = []
    seen = set()
    tries = 0
    cap = max(5000, count * 20)
    while len(out) < count and tries < cap:
        tries += 1
        c = generate_password(inputs, min_len, max_len, method=method, policy=policy)
        if c in seen: continue
        seen.add(c)
        out.append(c)
    return out
