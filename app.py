# app.py
import os
import time
import uuid
import json
import re
import sqlite3
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, jsonify,
    send_file, abort, Response, stream_with_context
)

from utils.password_strength import analyze_password
from utils.wordlist_gen import generate_password, generate_passwords, get_policy_by_name
from utils.hash_cracker import (
    crack_hash_from_list, crack_hash_with_file, count_lines_in_file
)
import os, json, uuid, time
from flask import make_response, render_template_string, url_for
os.makedirs("generated/reports", exist_ok=True)

# ==== App bootstrap ====
app = Flask(__name__, static_folder="static", template_folder="templates")
os.makedirs("generated", exist_ok=True)
DB_PATH = os.environ.get("HISTORY_DB", "history.db")
API_KEY = os.environ.get("API_KEY")  # if set, protects mutating endpoints

# ==== DB helpers ====
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT, ip TEXT, action TEXT, detail TEXT
      )
    """)
    cur.execute("""
      CREATE TABLE IF NOT EXISTS cracks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        algorithm TEXT, target_hash TEXT,
        salt TEXT, salt_pos TEXT,
        wordlist_file TEXT,
        found INTEGER, password TEXT
      )
    """)
    conn.commit()
    conn.close()

init_db()

def log(action, detail=""):
    # persist in SQLite (replaces in-memory HISTORY)  
    conn = db()
    conn.execute(
        "INSERT INTO events(time, ip, action, detail) VALUES (?,?,?,?)",
        (time.strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr, action, detail)
    )
    conn.commit()
    conn.close()

# ==== Security: API key + simple rate-limit ====
def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if API_KEY:
            supplied = request.headers.get("X-API-Key") or request.args.get("api_key")
            if supplied != API_KEY:
                return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

_RATE = {}
def rate_limit(name, limit=20, per_sec=60):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "?"
            now = time.time()
            key = (ip, name)
            timestamps = [t for t in _RATE.get(key, []) if now - t < per_sec]
            if len(timestamps) >= limit:
                return jsonify({"error": f"Rate limit exceeded for {name}"}), 429
            timestamps.append(now)
            _RATE[key] = timestamps
            return fn(*args, **kwargs)
        return wrapper
    return deco

# ==== Requirements / helpers ====
CHARSET_RE = re.compile(r'(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])')

def meets_requirements(pw, min_len):
    if not pw or len(pw) < min_len:
        return False
    return bool(CHARSET_RE.search(pw))

# ---------- Report model helpers ----------
def _get_analysis_for_report(payload: dict):
    # Reuse your analyzer that api_analyze already calls
    pw = payload.get("password", "")
    algo = payload.get("algorithm") or payload.get("hash_algo", "sha256")
    hw = payload.get("hardware", "gpu-consumer")
    try:
        return analyze_password(pw, hash_algo=algo, hardware=hw)
    except Exception as e:
        return {
            "score": None, "entropy": None, "zxcvbn_score": None,
            "time_to_crack": "N/A", "guesses_human": "N/A",
            "checklist": {}, "recommendations": [f"Analyzer error: {e}"]
        }

def _build_report_model(analysis: dict, payload: dict):
    pw = payload.get("password", "")
    masked = pw[:2] + "*" * max(0, len(pw)-4) + pw[-2:] if pw else "(no password)"
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "policy": payload.get("policy", "default"),
        "algorithm": payload.get("algorithm") or payload.get("hash_algo", "sha256"),
        "inputs": {"password_masked": masked, "length": len(pw)},
        "score": analysis.get("score"),
        "entropy_bits": analysis.get("entropy"),
        "zxcvbn_score": analysis.get("zxcvbn_score"),
        "crack_estimate": analysis.get("time_to_crack"),
        "guesses_human": analysis.get("guesses_human"),
        "checklist": analysis.get("checklist", {}),
        "recommendations": analysis.get("recommendations", []),
        "notes": analysis.get("notes", []),
    }

HTML_REPORT_TMPL = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Password Analysis Report</title>
<style>
  :root{--bg:#0b1320;--card:#0e1a2b;--line:#203246;--txt:#e7f6ff;--muted:#9fd0e0;--acc:#00f5a0;}
  body{margin:0;background:linear-gradient(180deg,#08101c,#0b1320);color:var(--txt);font:14px/1.5 system-ui,Segoe UI,Roboto,Arial}
  .wrap{max-width:900px;margin:24px auto;padding:0 16px}
  .head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
  .brand{display:flex;align-items:center;gap:10px}
  .orb{width:26px;height:26px;border-radius:50%;background:linear-gradient(90deg,#00f5a0,#5af0ff);box-shadow:0 0 22px rgba(90,245,255,.35)}
  h1{font-size:20px;margin:0}
  .small{color:var(--muted);font-size:12px}
  .card{background:linear-gradient(180deg,rgba(255,255,255,.03),rgba(255,255,255,.015));border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:14px;margin:10px 0}
  .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
  .kv{display:flex;justify-content:space-between;border-bottom:1px dashed var(--line);padding:6px 0}
  .pill{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.12);margin-right:6px}
  .good{color:#00f5a0;border-color:#00f5a0}.bad{color:#ff7a7a;border-color:#ff7a7a}
  .btn{display:inline-block;padding:10px 14px;border-radius:8px;border:1px solid rgba(255,255,255,.16);color:var(--txt);text-decoration:none}
  .btn-primary{background:linear-gradient(90deg,#00f5a0,#5af0ff);color:#022;border:none}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
</style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <div class="brand"><div class="orb"></div><h1>Password Analysis Report</h1></div>
      <div class="small">Generated: {{m.generated_at}}</div>
    </div>

    <div class="card">
      <div class="grid">
        <div>
          <div class="kv"><div>Policy</div><div class="mono">{{m.policy}}</div></div>
          <div class="kv"><div>Algorithm</div><div class="mono">{{m.algorithm}}</div></div>
          <div class="kv"><div>Password</div><div class="mono">{{m.inputs.password_masked}}</div></div>
        </div>
        <div>
          <div class="kv"><div>Length</div><div>{{m.inputs.length}}</div></div>
          <div class="kv"><div>Entropy (bits)</div><div>{{m.entropy_bits}}</div></div>
          <div class="kv"><div>Estimated Crack Time</div><div>{{m.crack_estimate}}</div></div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Checklist</h3>
      {% set cl = m.checklist or {} %}
      {% if cl %}
        {% for k,v in cl.items() %}
          <span class="pill {{ 'good' if v else 'bad' }}">{{ '✔' if v else '✖' }} {{k.replace('_',' ')}}</span>
        {% endfor %}
      {% else %}<div class="small">No checklist data.</div>{% endif %}
    </div>

    <div class="card">
      <h3>Recommendations</h3>
      {% if m.recommendations %}
        <ul>{% for r in m.recommendations %}<li>{{r}}</li>{% endfor %}</ul>
      {% else %}<div class="small">No recommendations.</div>{% endif %}
    </div>

    {% if m.notes and m.notes|length %}
    <div class="card"><h3>Notes</h3><ul>{% for n in m.notes %}<li>{{n}}</li>{% endfor %}</ul></div>
    {% endif %}

    <div class="card" style="display:flex;justify-content:space-between;align-items:center;">
      <div class="small">This HTML matches the PDF content.</div>
      <a class="btn btn-primary" href="{{ pdf_url }}">Download Report (PDF)</a>
    </div>
  </div>
</body>
</html>
"""
@app.route("/")
def home():
    return render_template("index.html")

# ---------- Create & View Report (HTML first, then PDF) ----------
@app.route("/api/analyze", methods=["POST"])
@require_api_key
@rate_limit("analyze", limit=25, per_sec=60)
def api_analyze():
    payload = request.get_json(silent=True) or {}

    pw = payload.get("password", "")
    if not pw:
        return jsonify({"error": "password required"}), 400

    algo = payload.get("algorithm") or payload.get("hash_algo", "sha256")
    hw = payload.get("hardware", "gpu-consumer")

    try:
        analysis = analyze_password(pw, hash_algo=algo, hardware=hw)
    except Exception as e:
        analysis = {
            "score": None, "entropy": None, "zxcvbn_score": None,
            "time_to_crack": "N/A", "guesses_human": "N/A",
            "checklist": {}, "recommendations": [f"Analyzer error: {e}"]
        }

    log("Analyze Password", f"len={len(pw)}, algo={algo}, hw={hw}")
    return jsonify(analysis)

@app.route("/api/report/create", methods=["POST"])
@require_api_key
@rate_limit("report_create", limit=25, per_sec=60)
def api_report_create():
    payload = request.get_json(silent=True) or {}
    # Accept both algorithm and legacy hash_algo key
    if not payload.get("algorithm") and payload.get("hash_algo"):
        payload["algorithm"] = payload["hash_algo"]

    # Minimal validation
    if not payload.get("password"):
        return jsonify({"error": "password required"}), 400

    analysis = _get_analysis_for_report(payload)
    model = _build_report_model(analysis, payload)

    rid = uuid.uuid4().hex
    with open(os.path.join("generated", "reports", f"{rid}.json"), "w", encoding="utf-8") as f:
        json.dump(model, f, ensure_ascii=False)

    log("Report Create", f"id={rid}, policy={model.get('policy')}")
    return jsonify({"report_id": rid, "url": url_for("view_report", report_id=rid)})

@app.route("/report/<report_id>", methods=["GET"])
def view_report(report_id):
    path = os.path.join("generated", "reports", f"{report_id}.json")
    if not os.path.exists(path):
        return "Report not found", 404
    with open(path, "r", encoding="utf-8") as f:
        model = json.load(f)
    html = render_template_string(HTML_REPORT_TMPL, m=model,
                                  pdf_url=url_for("api_report_pdf", report_id=report_id))
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/api/report/<report_id>/pdf", methods=["GET"])
@rate_limit("report_pdf", limit=25, per_sec=60)
def api_report_pdf(report_id):
    """
    HTML-to-PDF using WeasyPrint.
    Generates a PDF that matches the /report/<id> HTML (same template + theme).
    """
    # 1) Load the saved report model
    path = os.path.join("generated", "reports", f"{report_id}.json")
    if not os.path.exists(path):
        return jsonify({"error": "Report not found"}), 404
    with open(path, "r", encoding="utf-8") as f:
        m = json.load(f)

    # 2) Render the EXACT SAME HTML you serve at /report/<id>
    #    (We keep pdf_url in the template for consistency, but it won't be clicked in PDF)
    html_str = render_template_string(
        HTML_REPORT_TMPL,
        m=m,
        pdf_url=url_for("api_report_pdf", report_id=report_id)
    )

    # 3) Prepare styles for WeasyPrint
    # Try to include your site theme CSS if present. Your index.html expects it at static/css/style.css.
    # We'll search a few common locations so it "just works" in dev or prod.
    css_candidates = [
        os.path.join(app.static_folder or "static", "css", "style.css"),
        os.path.join("static", "css", "style.css"),
        os.path.join("static", "style.css"),
        "style.css",  # fallback if your file is at repo root during dev
    ]
    stylesheets = []
    try:
        from weasyprint import HTML, CSS
        for p in css_candidates:
            if os.path.exists(p):
                stylesheets.append(CSS(filename=os.path.abspath(p)))
                break  # use the first one that exists

        # Add small print-tweaks so it paginates nicely (no theme changes)
        stylesheets.append(CSS(string="""
            @page { size: A4; margin: 2mm 2mm; }
            body { background: #0b1320 !important; color: #e7f6ff !important; }
            .card { page-break-inside: avoid; }
            .grid { break-inside: avoid; }
            .btn-primary { display: none !important; }
        """))

        # 4) Convert to PDF (base_url is critical for resolving relative assets)
        pdf_bytes = HTML(string=html_str, base_url=request.url_root).write_pdf(
            stylesheets=stylesheets
        )
    except Exception as e:
        # If WeasyPrint fails, return a helpful error (avoid silent 500s)
        return jsonify({"error": f"WeasyPrint render failed: {e}"}), 500

    # 5) Log + send
    log("Report PDF", f"id={report_id}")
    resp = make_response(pdf_bytes)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = f"attachment; filename=analysis_report_{report_id}.pdf"
    return resp


# ---------- Generation ----------
@app.route("/api/generate", methods=["POST"])
@require_api_key
@rate_limit("generate", limit=20, per_sec=60)
def api_generate():
    data = request.json or {}
    mode = data.get("mode", "password")
    inputs = data.get("inputs", {})
    policy_name = data.get("policy", "default")
    policy = get_policy_by_name(policy_name)           # new
    try: min_len = max(7, int(data.get("min_len", policy["min_len"])))
    except: min_len = policy["min_len"]
    try: max_len = int(data.get("max_len", max(policy["min_len"], policy["max_len"])))
    except: max_len = max(policy["min_len"], policy["max_len"])
    try: limit = int(data.get("limit", 1000))
    except: limit = 1000
    try: count = int(data.get("count", 1))             # batch passwords
    except: count = 1
    method = data.get("method", "all")

    os.makedirs("generated", exist_ok=True)

    if mode == "password":
        pwds = generate_passwords(inputs, min_len, max_len, count=count, method=method, policy=policy)  # batch  
        log("Generate Password", f"{len(pwds)} item(s)")
        return jsonify({"passwords": pwds})

    # wordlist mode (unchanged, but policy-aware)
    token = uuid.uuid4().hex[:12]
    filename = f"wordlist_{token}.txt"
    filepath = os.path.join("generated", filename)

    unique = set()
    attempts = 0
    max_attempts = max(limit * 8, 5000)
    with open(filepath, "w", encoding="utf-8") as fh:
        while len(unique) < limit and attempts < max_attempts:
            attempts += 1
            c = generate_password(inputs, min_len, max_len, method=method, policy=policy)
            if not c or not meets_requirements(c, min_len):
                continue
            if c in unique:
                continue
            unique.add(c)
            fh.write(c + "\n")

    count_out = len(unique)
    if count_out == 0:
        try: os.remove(filepath)
        except: pass
        log("Generate Wordlist", "failed")
        return jsonify({"error": "failed"}), 500
    log("Generate Wordlist", f"{filename} ({count_out})")
    return jsonify({"file_id": token, "filename": filename, "count": count_out})

# Streaming generation (unchanged output schema; UI updated to consume)
@app.route("/api/generate_stream", methods=["POST"])
@require_api_key
@rate_limit("generate_stream", limit=10, per_sec=60)
def api_generate_stream():
    data = request.json or {}
    mode = data.get("mode", "password")
    inputs = data.get("inputs", {})
    policy = get_policy_by_name(data.get("policy", "default"))
    try: min_len = max(7, int(data.get("min_len", policy["min_len"])))
    except: min_len = policy["min_len"]
    try: max_len = int(data.get("max_len", max(policy["min_len"], policy["max_len"])))
    except: max_len = max(policy["min_len"], policy["max_len"])
    try: limit = int(data.get("limit", 1000))
    except: limit = 1000
    method = data.get("method", "all")

    def nd(obj):
        return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")

    from utils.wordlist_gen import ensure_requirements as _ensure  # reuse  

    def stream_password():
        yield nd({"type":"progress","pct":0,"message":"starting"})
        # emit a few live candidates to show pipeline
        for pct in [10, 30, 60, 85]:
            c = generate_password(inputs, max(4, min_len//2), max_len, method=method, policy=policy)
            yield nd({"type":"live","candidate":c})
            yield nd({"type":"progress","pct":pct,"message":f"stage {pct}%"})
        # final
        final = generate_password(inputs, min_len, max_len, method=method, policy=policy)
        yield nd({"type":"progress","pct":100,"message":"done"})
        yield nd({"type":"done","mode":"password","password":final})
        log("Generate Password (stream)", final)

    def stream_wordlist():
        token = uuid.uuid4().hex[:12]
        filename = f"wordlist_{token}.txt"
        filepath = os.path.join("generated", filename)
        unique = set()
        attempts = 0
        max_attempts = max(limit * 8, 500000)
        last_pct = -1
        yield nd({"type":"progress","pct":0,"message":"starting"})
        yield nd({"type":"live","candidate":"initializing seeds"})
        with open(filepath, "w", encoding="utf-8") as fh:
            while len(unique) < limit and attempts < max_attempts:
                attempts += 1
                c = generate_password(inputs, min_len, max_len, method=method, policy=policy)
                if not c or not _ensure(c, min_len, policy=policy):
                    if attempts % 500 == 0:
                        yield nd({"type":"live","candidate":"searching for valid candidates..."})
                    continue
                if c in unique:
                    continue
                unique.add(c)
                fh.write(c + "\n")
                if len(unique) <= 10 or len(unique) % max(1, limit//20) == 0:
                    yield nd({"type":"live","candidate":c})
                pct = int((len(unique)/limit)*100)
                if pct != last_pct:
                    last_pct = pct
                    yield nd({"type":"progress","pct":pct,"message":f"{len(unique)}/{limit}"})
        count = len(unique)
        if count == 0:
            try: os.remove(filepath)
            except: pass
            yield nd({"type":"error","message":"failed to generate any entries"})
            log("Generate Wordlist (stream)","failed")
        else:
            yield nd({"type":"progress","pct":100,"message":"completed"})
            yield nd({"type":"done","mode":"wordlist","file_id":token,"filename":filename,"count":count})
            log("Generate Wordlist (stream)", f"{filename} ({count})")

    if mode == "password":
        return Response(stream_with_context(stream_password()), mimetype="application/x-ndjson")
    else:
        return Response(stream_with_context(stream_wordlist()), mimetype="application/x-ndjson")

@app.route("/api/download/<file_id>", methods=["GET"])
def api_download(file_id):
    dirpath = "generated"
    if not os.path.isdir(dirpath):
        abort(404)
    for fn in os.listdir(dirpath):
        if fn.startswith(f"wordlist_{file_id}"):
            return send_file(os.path.join(dirpath, fn), as_attachment=True, download_name=fn)
    abort(404)


# ---------- Wordlist upload (drag & drop or browse) ----------
@app.route("/api/upload_wordlist", methods=["POST"])
@require_api_key
@rate_limit("upload", limit=12, per_sec=60)
def api_upload_wordlist():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f = request.files["file"]

    # ✅ Enforce max file size (5 MB) before saving
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)
    if size > 5 * 1024 * 1024:
        log("Upload Wordlist (rejected)", f"too large: {size} bytes")
        return jsonify({"error": "File too large (max 5 MB)"}), 400

    token = uuid.uuid4().hex[:12]
    filename = f"wordlist_{token}.txt"
    path = os.path.join("generated", filename)
    f.save(path)
    log("Upload Wordlist", filename)

    return jsonify({"file_id": token, "filename": filename})


# ---------- Cracking (with progress + salted support) ----------
@app.route("/api/crack_stream", methods=["POST"])
@require_api_key
@rate_limit("crack", limit=8, per_sec=60)
def api_crack_stream():
    # --- Handle both JSON and FormData (without uploads) ---
    data = {}
    if request.is_json:
        data = request.get_json(force=True)
        algo = (data.get("algorithm") or "").lower()
        target_hash = data.get("hash")
        salt = data.get("salt") or ""
        salt_pos = data.get("salt_pos", "suffix")
        pasted = data.get("wordlist")  # optional array
        file_id = data.get("file_id")  # must come from upload/generate
    else:
        algo = (request.form.get("algorithm") or "").lower()
        target_hash = request.form.get("hash")
        salt = request.form.get("salt") or ""
        salt_pos = request.form.get("salt_pos", "suffix")
        pasted = None
        file_id = request.form.get("file_id")

    attempt_limit = int(request.form.get("attempt_limit") or data.get("attempt_limit", 1_000_000))

    if not algo or not target_hash:
        return jsonify({"error": "algorithm and hash required"}), 400

    def nd(obj): 
        return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")

    def stream():
        # ----- Case 1: client-sent wordlist array -----
        if isinstance(pasted, list) and pasted:
            total = len(pasted)
            yield nd({"type": "meta", "source": "client_list", "total": total})
            found = None
            for idx, w in enumerate(pasted[:attempt_limit], 1):
                if crack_hash_from_list(algo, target_hash, [w], salt=salt, salt_pos=salt_pos, attempt_limit=1):
                    found = w
                    break
                if idx % max(1, total // 100) == 0:
                    yield nd({"type": "progress", "done": idx, "total": total, "pct": int(idx * 100 / total)})
            if found:
                yield nd({"type": "done", "found": True, "password": found})
                conn = db(); conn.execute(
                    "INSERT INTO cracks(created_at,algorithm,target_hash,salt,salt_pos,wordlist_file,found,password) VALUES(?,?,?,?,?,?,?,?)",
                    (time.strftime("%Y-%m-%d %H:%M:%S"), algo, target_hash, salt, salt_pos, "client_list", 1, found)
                ); conn.commit(); conn.close()
                log("Crack (client list)", f"{algo}, found=True")
            else:
                yield nd({"type": "done", "found": False})
                conn = db(); conn.execute(
                    "INSERT INTO cracks(created_at,algorithm,target_hash,salt,salt_pos,wordlist_file,found,password) VALUES(?,?,?,?,?,?,?,?)",
                    (time.strftime("%Y-%m-%d %H:%M:%S"), algo, target_hash, salt, salt_pos, "client_list", 0, None)
                ); conn.commit(); conn.close()
                log("Crack (client list)", f"{algo}, found=False")
            return

        # ----- Case 2: uploaded/generated wordlist by file_id -----
        file_path = None
        if file_id:
            for fn in os.listdir("generated"):
                if fn.startswith(f"wordlist_{file_id}") and fn.endswith(".txt"):
                    file_path = os.path.join("generated", fn)
                    break

        if not file_path:
            yield nd({"type": "error", "message": "No wordlist available; upload or generate one."})
            return

        total = count_lines_in_file(file_path)
        yield nd({"type": "meta", "source": os.path.basename(file_path), "total": total})

        done = 0
        found_pw = None
        from utils.hash_cracker import hash_word

        try:
            import hashlib, bcrypt
            _BCRYPT_OK = True
        except Exception:
            _BCRYPT_OK = False

        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if done >= attempt_limit:
                    break
                w = line.strip()
                if not w:
                    continue
                done += 1
                if algo == "bcrypt":
                    if _BCRYPT_OK:
                        try:
                            import bcrypt  # noqa
                            if bcrypt.checkpw(w.encode(), target_hash.encode()):
                                found_pw = w; break
                        except Exception:
                            pass
                else:
                    if salt:
                        hw = hash_word((salt + w) if salt_pos == "prefix" else (w + salt), algo)
                    else:
                        hw = hash_word(w, algo)
                    if hw == target_hash:
                        found_pw = w; break

                if done % max(1, total // 100) == 0:
                    yield nd({"type": "progress", "done": done, "total": total, "pct": int(done * 100 / max(1, total)), "last": w})

        if found_pw:
            yield nd({"type": "done", "found": True, "password": found_pw})
            conn = db(); conn.execute(
                "INSERT INTO cracks(created_at,algorithm,target_hash,salt,salt_pos,wordlist_file,found,password) VALUES(?,?,?,?,?,?,?,?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), algo, target_hash, salt, salt_pos, os.path.basename(file_path), 1, found_pw)
            ); conn.commit(); conn.close()
            log("Crack (server file)", f"{algo}, file={os.path.basename(file_path)}, found=True")
        else:
            yield nd({"type": "done", "found": False})
            conn = db(); conn.execute(
                "INSERT INTO cracks(created_at,algorithm,target_hash,salt,salt_pos,wordlist_file,found,password) VALUES(?,?,?,?,?,?,?,?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), algo, target_hash, salt, salt_pos, os.path.basename(file_path), 0, None)
            ); conn.commit(); conn.close()
            log("Crack (server file)", f"{algo}, file={os.path.basename(file_path)}, found=False")

    return Response(stream_with_context(stream()), mimetype="application/x-ndjson")

# ---------- History ----------
@app.route("/api/history")
def api_history():
    conn = db()
    rows = conn.execute("SELECT time, action, detail FROM events ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "t": time.time()})
    
@app.route("/api/history/clear", methods=["POST"])
@require_api_key
def api_clear_history():
    conn = db()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    log("History Cleared")
    return jsonify({"status": "cleared"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
