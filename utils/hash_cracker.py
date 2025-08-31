# utils/hash_cracker.py
import hashlib
try:
    import bcrypt
    _BCRYPT_OK = True
except Exception:
    _BCRYPT_OK = False

def hash_word(word: str, algo: str) -> str:
    algo = (algo or "").lower()
    if algo == "md5":
        return hashlib.md5(word.encode()).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(word.encode()).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(word.encode()).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(word.encode()).hexdigest()
    return None

def count_lines_in_file(path: str) -> int:
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def crack_hash_from_list(algo: str, target_hash: str, wordlist: list, attempt_limit=250000, salt: str = "", salt_pos: str = "suffix"):
    algo = (algo or "").lower()
    salted = bool(salt)
    for idx, w in enumerate(wordlist):
        if idx >= attempt_limit:
            break
        if algo == "bcrypt":
            if not _BCRYPT_OK: continue
            try:
                if bcrypt.checkpw(w.encode(), target_hash.encode()):
                    return w
            except Exception:
                continue
        else:
            candidate = (salt + w) if (salted and salt_pos=="prefix") else (w + salt if salted else w)
            if hash_word(candidate, algo) == target_hash:
                return w
    return None

def crack_hash_with_file(algo: str, target_hash: str, filepath: str, attempt_limit=250000, salt: str = "", salt_pos: str = "suffix", progress_cb=None):
    algo = (algo or "").lower()
    salted = bool(salt)
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            for idx, line in enumerate(fh):
                if idx >= attempt_limit:
                    break
                if progress_cb and (idx % 1000 == 0):
                    try: progress_cb(idx)
                    except: pass
                w = line.strip()
                if not w: continue
                if algo == "bcrypt":
                    if not _BCRYPT_OK: continue
                    try:
                        if bcrypt.checkpw(w.encode(), target_hash.encode()):
                            return w
                    except Exception:
                        continue
                else:
                    candidate = (salt + w) if (salted and salt_pos=="prefix") else (w + salt if salted else w)
                    if hash_word(candidate, algo) == target_hash:
                        return w
        return None
    except FileNotFoundError:
        return None
