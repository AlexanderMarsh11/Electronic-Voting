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
    election_id = int(request.args.get("election_id", "1"))

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        "SELECT id, title, status, ballot_open, ballot_close FROM elections WHERE id=%s",
        (election_id,)
    )
    election = cur.fetchone()
    if not election:
        abort(404, "Election not found")

    cur.execute(
        "SELECT display_name FROM candidates WHERE election_id=%s ORDER BY id",
        (election_id,)
    )
    candidates = [r["display_name"] for r in cur.fetchall()]

    return render_template("vote.html", election=election, election_id=election_id, candidates=candidates)

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

    # User upsert
    national_hash = hashlib.sha256(national_id.encode()).hexdigest()

    cur.execute(
        "SELECT id, eligible FROM users WHERE national_id_hash=%s",
        (national_hash,)
    )
    user = cur.fetchone()

    if not user:
        # MVP placeholder public key (you can later replace with real keypair from browser)
        placeholder_pub = "-----BEGIN PUBLIC KEY-----\nPLACEHOLDER\n-----END PUBLIC KEY-----"
        cur.execute(
            "INSERT INTO users (national_id_hash, public_key_pem, district, eligible, created_at) VALUES (%s,%s,%s,1,%s)",
            (national_hash, placeholder_pub, district, now)
        )
        user_id = cur.lastrowid
    else:
        user_id = user["id"]
        if not user["eligible"]:
            abort(403, "User not eligible")

    # Prevent double voting (MVP)
    cur.execute(
        "SELECT 1 FROM votes WHERE election_id=%s AND user_id=%s",
        (election_id, user_id)
    )
    if cur.fetchone():
        abort(400, "User already voted")

    # Encrypt vote bundle on server (MVP)
    vote_obj = {"candidate": candidate, "ts": now.isoformat() + "Z"}
    plaintext = json.dumps(vote_obj).encode()

    pubkey = load_election_public_key(election["public_key_pem"])
    bundle = encrypt_vote_bundle(plaintext, pubkey)

    # Store vote
    cur.execute(
        "INSERT INTO votes (election_id, user_id, ciphertext, created_at) VALUES (%s,%s,%s,%s)",
        (election_id, user_id, bundle, now)
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

    cur.execute("SELECT COUNT(*) AS c FROM users")
    users_count = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM votes")
    votes_count = cur.fetchone()["c"]

    return render_template(
        "admin.html",
        elections=elections,
        users_count=users_count,
        votes_count=votes_count,
        token=request.args.get("token", "")
    )

@app.post("/admin/elections/<int:election_id>/open")
def admin_open_election(election_id: int):
    require_admin()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    # Open voting window for next 2 hours
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

    # Insert candidate
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

    if election["status"] == "closed":
        return jsonify({"message": "already closed"})

    private_key = load_election_private_key(election["private_key_path"])

    cur.execute("SELECT display_name FROM candidates WHERE election_id=%s", (election_id,))
    valid_names = set([c["display_name"] for c in cur.fetchall()])

    cur.execute("SELECT ciphertext FROM votes WHERE election_id=%s", (election_id,))
    rows = cur.fetchall()

    tally = {}
    invalid_votes = 0

    for r in rows:
        try:
            plaintext = decrypt_vote_bundle(r["ciphertext"], private_key)
            vote_obj = json.loads(plaintext.decode())
            candidate = vote_obj.get("candidate", "").strip()

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

    # Required column: published_hashes (NOT NULL)
    published_hashes = [hashlib.sha256(r["ciphertext"]).hexdigest() for r in rows]

    cur.execute("UPDATE elections SET status='closed' WHERE id=%s", (election_id,))
    cur.execute(
        "INSERT INTO results (election_id, results_json, published_hashes, published_at) VALUES (%s,%s,%s,%s)",
        (election_id, json.dumps(results), json.dumps(published_hashes), now_utc())
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)