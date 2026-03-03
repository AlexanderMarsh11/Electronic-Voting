import os
import json
import hashlib
import datetime as dt
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

import mysql.connector
from flask import Flask, request, jsonify, abort, render_template, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# =========================
# Config
# =========================
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_NAME = os.getenv("DB_NAME", "electronic_voting")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
KEYS_DIR = os.getenv("KEYS_DIR", "./keys")

Path(KEYS_DIR).mkdir(parents=True, exist_ok=True)

# =========================
# Helpers
# =========================
def db_conn():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        autocommit=True
    )

def now_utc():
    return dt.datetime.utcnow().replace(microsecond=0)

def require_admin():
    # Allows admin token via header OR query param OR form (to make browser admin easy)
    token = (
        request.headers.get("X-Admin-Token", "")
        or request.args.get("token", "")
        or request.form.get("token", "")
    )
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        abort(403, description="Admin token missing/invalid")

# =========================
# Key Handling
# =========================
def load_election_private_key(path: str):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)

def load_election_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode())

def decrypt_vote_bundle(bundle: bytes, election_private_key):
    # RSA-3072 ciphertext length = 384 bytes
    RSA_LEN = 384
    IV_LEN = 12

    enc_key = bundle[:RSA_LEN]
    iv = bundle[RSA_LEN:RSA_LEN + IV_LEN]
    ct = bundle[RSA_LEN + IV_LEN:]

    aes_key = election_private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ct, None)

def encrypt_vote_bundle(plaintext: bytes, election_public_key):
    aes_key = os.urandom(32)   # AES-256
    iv = os.urandom(12)        # GCM nonce

    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(iv, plaintext, None)

    enc_key = election_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return enc_key + iv + ct

def generate_election_keypair(election_id: int):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = Path(KEYS_DIR) / f"election_{election_id}_private.pem"
    priv_path.write_bytes(priv_pem)
    os.chmod(priv_path, 0o600)

    return pub_pem.decode(), str(priv_path)

# =========================
# Routes
# =========================
@app.get("/")
def health():
    return jsonify({"status": "ok"})

# -------------------------
# USER: Register + Vote
# -------------------------
@app.get("/vote")
def vote_page():
    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    # Fetch all elections (newest first)
    cur.execute(
        "SELECT id, title, status, ballot_open, ballot_close FROM elections ORDER BY id DESC"
    )
    elections = cur.fetchall()

    if not elections:
        abort(404, "No elections found")

    # If the user did not select an election_id,
    # automatically choose the most recent OPEN election.
    # If none are open, choose the most recent election.
    election_id_arg = request.args.get("election_id")

    if election_id_arg:
        try:
            election_id = int(election_id_arg)
        except ValueError:
            abort(400, "Invalid election_id")
    else:
        open_ids = [e["id"] for e in elections if e["status"] == "open"]
        election_id = open_ids[0] if open_ids else elections[0]["id"]

    # Load the selected election details
    cur.execute(
        "SELECT id, title, status, ballot_open, ballot_close FROM elections WHERE id=%s",
        (election_id,)
    )
    election = cur.fetchone()

    if not election:
        abort(404, "Election not found")

    # Fetch candidates for the selected election
    cur.execute(
        "SELECT display_name FROM candidates WHERE election_id=%s ORDER BY id",
        (election_id,)
    )
    candidates = [r["display_name"] for r in cur.fetchall()]

    return render_template(
        "vote.html",
        election=election,
        election_id=election_id,
        elections=elections,   # Used for the election dropdown menu
        candidates=candidates
    )

@app.post("/vote")
def vote_submit():
    election_id = int(request.form.get("election_id", "0"))
    national_id = (request.form.get("national_id") or "").strip()
    district = (request.form.get("district") or "A").strip()[:1]
    candidate = (request.form.get("candidate") or "").strip()

    if not election_id or not national_id or not candidate:
        abort(400, "Missing fields")

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    # Load election
    cur.execute(
        "SELECT id, title, status, ballot_open, ballot_close, public_key_pem FROM elections WHERE id=%s",
        (election_id,)
    )
    election = cur.fetchone()
    if not election:
        abort(404, "Election not found")

    # Check open window
    now = now_utc()
    if election["status"] != "open":
        abort(400, "Election is not open")
    if now < election["ballot_open"] or now > election["ballot_close"]:
        abort(400, "Voting window closed")

    # Validate candidate
    cur.execute(
        "SELECT 1 FROM candidates WHERE election_id=%s AND display_name=%s",
        (election_id, candidate)
    )
    if not cur.fetchone():
        abort(400, "Invalid candidate")

    # User upsert (kept for eligibility + candidate FK design)
    national_hash_hex = hashlib.sha256(national_id.encode()).hexdigest()

    cur.execute(
        "SELECT id, eligible FROM users WHERE national_id_hash=%s",
        (national_hash_hex,)
    )
    user = cur.fetchone()

    if not user:
        placeholder_pub = "-----BEGIN PUBLIC KEY-----\nPLACEHOLDER\n-----END PUBLIC KEY-----"
        cur.execute(
            "INSERT INTO users (national_id_hash, public_key_pem, district, eligible, created_at) VALUES (%s,%s,%s,1,%s)",
            (national_hash_hex, placeholder_pub, district, now)
        )
    else:
        if not user["eligible"]:
            abort(403, "User not eligible")

    # ✅ votes table uses credential_hash (BINARY(32)) not user_id
    credential_hash = hashlib.sha256(national_id.encode()).digest()

    # Prevent double voting (one credential per election)
    cur.execute(
        "SELECT 1 FROM votes WHERE election_id=%s AND credential_hash=%s",
        (election_id, credential_hash)
    )
    if cur.fetchone():
        abort(400, "User already voted")

    # Encrypt vote bundle on server (MVP)
    vote_obj = {"candidate": candidate, "ts": now.isoformat() + "Z"}
    plaintext = json.dumps(vote_obj).encode()

    pubkey = load_election_public_key(election["public_key_pem"])
    bundle = encrypt_vote_bundle(plaintext, pubkey)

    ballot_hash = hashlib.sha256(bundle).digest()

    # ✅ Store vote with your actual schema
    cur.execute(
        "INSERT INTO votes (election_id, credential_hash, ciphertext, ballot_hash, submitted_at) VALUES (%s,%s,%s,%s,%s)",
        (election_id, credential_hash, bundle, ballot_hash, now)
    )

    return render_template("vote_done.html", election_id=election_id)

# -------------------------
# ADMIN: Dashboard + Open + Close + Candidates + Results
# -------------------------
@app.get("/admin")
def admin_page():
    require_admin()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT id, title, status, ballot_open, ballot_close FROM elections ORDER BY id DESC")
    elections = cur.fetchall()

    selected_id = request.args.get("election_id")
    selected_id = int(selected_id) if selected_id else (elections[0]["id"] if elections else None)

    selected_election = None
    candidates = []
    latest_results = None
    latest_published_at = None

    if selected_id:
        cur.execute("SELECT id, title, status, ballot_open, ballot_close FROM elections WHERE id=%s", (selected_id,))
        selected_election = cur.fetchone()

        cur.execute("SELECT id, display_name FROM candidates WHERE election_id=%s ORDER BY id", (selected_id,))
        candidates = cur.fetchall()

        cur.execute(
            "SELECT results_json, published_at FROM results WHERE election_id=%s ORDER BY published_at DESC LIMIT 1",
            (selected_id,)
        )
        row = cur.fetchone()
        if row:
            latest_results = json.loads(row["results_json"])
            latest_published_at = row["published_at"]

    cur.execute("SELECT COUNT(*) AS c FROM users")
    users_count = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM votes")
    votes_count = cur.fetchone()["c"]

    return render_template(
        "admin.html",
        elections=elections,
        selected_id=selected_id,
        selected_election=selected_election,
        candidates=candidates,
        latest_results=latest_results,
        latest_published_at=latest_published_at,
        users_count=users_count,
        votes_count=votes_count,
        token=request.args.get("token", "")
    )


@app.post("/admin/elections/<int:election_id>/open")
def admin_open_election(election_id: int):
    require_admin()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        "UPDATE elections SET status='open', ballot_open=%s, ballot_close=%s WHERE id=%s",
        (now_utc() - dt.timedelta(hours=1), now_utc() + dt.timedelta(hours=2), election_id)
    )
    return redirect(url_for("admin_page", token=request.args.get("token", "")))

@app.post("/admin/elections/<int:election_id>/candidates/add")
def admin_add_candidate(election_id: int):
    require_admin()

    display_name = (request.form.get("display_name") or "").strip()
    if not display_name:
        abort(400, "display_name required")

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    # Because candidates table requires user_id (FK), we create a "candidate user profile" automatically.
    candidate_hash = hashlib.sha256(f"candidate:{election_id}:{display_name}".encode()).hexdigest()
    placeholder_pub = "-----BEGIN PUBLIC KEY-----\nCANDIDATE_PROFILE\n-----END PUBLIC KEY-----"

    cur.execute("SELECT id FROM users WHERE national_id_hash=%s", (candidate_hash,))
    u = cur.fetchone()
    if not u:
        cur.execute(
            "INSERT INTO users (national_id_hash, public_key_pem, district, eligible, created_at) VALUES (%s,%s,%s,1,%s)",
            (candidate_hash, placeholder_pub, "A", now_utc())
        )
        user_id = cur.lastrowid
    else:
        user_id = u["id"]

    cur.execute(
        "INSERT INTO candidates (election_id, user_id, display_name, created_at) VALUES (%s,%s,%s,%s)",
        (election_id, user_id, display_name, now_utc())
    )

    return redirect(url_for("admin_page", token=request.args.get("token", "")))

# -------------------------
# Admin Close Election (Decrypt + Tally)  (FIXED published_hashes)
# -------------------------
@app.post("/admin/elections/<int:election_id>/close")
def admin_close_election(election_id: int):
    require_admin()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT status, private_key_path FROM elections WHERE id=%s", (election_id,))
    election = cur.fetchone()

    if not election:
        abort(404, "Election not found")

    # Allow recalculation when already closed
    force = request.args.get("force", "0") == "1"
    if election["status"] == "closed" and not force:
        return jsonify({"message": "already closed", "hint": "Add ?force=1 to recalculate"})

    private_key = load_election_private_key(election["private_key_path"])

    # Valid candidates
    cur.execute("SELECT display_name FROM candidates WHERE election_id=%s", (election_id,))
    valid_names = {c["display_name"] for c in cur.fetchall()}

    # Votes ciphertext
    cur.execute("SELECT ciphertext FROM votes WHERE election_id=%s", (election_id,))
    rows = cur.fetchall()

    tally: dict[str, int] = {}
    invalid_votes = 0

    for r in rows:
        try:
            plaintext = decrypt_vote_bundle(r["ciphertext"], private_key)
            vote_obj = json.loads(plaintext.decode())
            candidate = (vote_obj.get("candidate") or "").strip()

            if candidate in valid_names:
                tally[candidate] = tally.get(candidate, 0) + 1
            else:
                invalid_votes += 1
        except Exception:
            invalid_votes += 1

    winner = max(tally, key=tally.get) if tally else None

    results = {
        "total_votes": len(rows),
        "valid_votes": sum(tally.values()),
        "invalid_votes": invalid_votes,
        "tally": tally,
        "winner": winner
    }

    # Required by your schema (NOT NULL)
    published_hashes = [hashlib.sha256(r["ciphertext"]).hexdigest() for r in rows]

    # Mark election closed
    cur.execute("UPDATE elections SET status='closed' WHERE id=%s", (election_id,))

    # ✅ Save results safely: UPDATE first, INSERT if missing
    now = now_utc()
    cur.execute(
        "UPDATE results SET results_json=%s, published_hashes=%s, published_at=%s WHERE election_id=%s",
        (json.dumps(results), json.dumps(published_hashes), now, election_id)
    )
    if cur.rowcount == 0:
        cur.execute(
            "INSERT INTO results (election_id, results_json, published_hashes, published_at) VALUES (%s,%s,%s,%s)",
            (election_id, json.dumps(results), json.dumps(published_hashes), now)
        )

    return jsonify(results)

@app.get("/admin/results/<int:election_id>")
def admin_results(election_id: int):
    require_admin()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT id, title, status FROM elections WHERE id=%s", (election_id,))
    election = cur.fetchone()
    if not election:
        abort(404, "Election not found")

    cur.execute(
        "SELECT results_json, published_at FROM results WHERE election_id=%s ORDER BY published_at DESC LIMIT 1",
        (election_id,)
    )
    row = cur.fetchone()

    results = json.loads(row["results_json"]) if row else None
    published_at = row["published_at"] if row else None

    return render_template("results.html", election=election, results=results, published_at=published_at)

@app.get("/results/<int:election_id>")
def public_results(election_id: int):
    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT id, title, status FROM elections WHERE id=%s", (election_id,))
    election = cur.fetchone()
    if not election:
        abort(404, "Election not found")

    cur.execute(
        "SELECT results_json, published_at FROM results WHERE election_id=%s ORDER BY published_at DESC LIMIT 1",
        (election_id,)
    )
    row = cur.fetchone()

    results = json.loads(row["results_json"]) if row else None
    published_at = row["published_at"] if row else None

    return render_template("results.html", election=election, results=results, published_at=published_at)

@app.post("/admin/elections/create")
def admin_create_election():
    require_admin()

    title = (request.form.get("title") or "").strip()
    scope = (request.form.get("scope") or "global").strip()  # global | district
    district = (request.form.get("district") or "").strip()[:1] or None

    if not title:
        abort(400, "title required")
    if scope not in ("global", "district"):
        abort(400, "invalid scope")
    if scope == "district" and not district:
        abort(400, "district required for district-scope election")

    now = now_utc()
    filing_open = now
    filing_close = now + dt.timedelta(days=1)
    ballot_open = now
    ballot_close = now + dt.timedelta(hours=2)

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    # 1) Insert election row first (placeholder keys)
    cur.execute(
        """
        INSERT INTO elections
          (title, scope, district, filing_open, filing_close, ballot_open, ballot_close,
           public_key_pem, private_key_path, status, created_at)
        VALUES
          (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (title, scope, district, filing_open, filing_close, ballot_open, ballot_close,
         "PENDING", "PENDING", "draft", now)
    )
    election_id = cur.lastrowid

    # 2) Generate keypair and update row
    pub_pem, priv_path = generate_election_keypair(election_id)

    cur.execute(
        "UPDATE elections SET public_key_pem=%s, private_key_path=%s WHERE id=%s",
        (pub_pem, priv_path, election_id)
    )

    token = request.args.get("token", "")
    return redirect(url_for("admin_page", token=token, election_id=election_id))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)