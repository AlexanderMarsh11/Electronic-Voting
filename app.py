import os
import json
import base64
import hashlib
import datetime as dt
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

import mysql.connector
from flask import Flask, request, jsonify, abort, render_template
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

def parse_iso(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.strip().replace("Z", ""))

def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def require_admin():
    token = request.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        abort(403, description="Admin token missing/invalid")

# =========================
# Key Handling
# =========================
def load_election_private_key(path: str):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)

def decrypt_vote_bundle(bundle: bytes, election_private_key):
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

@app.get("/vote")
def vote_page():
    return render_template("vote.html")

# =========================
# Admin Close Election (Decrypt + Tally)
# =========================
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

    # ✅ FIX: published_hashes is required in results table (NOT NULL)
    # We publish SHA-256 hashes of each ciphertext for public audit/verifiability.
    published_hashes = []
    for r in rows:
        try:
            published_hashes.append(hashlib.sha256(r["ciphertext"]).hexdigest())
        except Exception:
            # If anything odd happens, still keep structure consistent
            published_hashes.append(None)

    cur.execute("UPDATE elections SET status='closed' WHERE id=%s", (election_id,))
    cur.execute(
        "INSERT INTO results (election_id, results_json, published_hashes, published_at) VALUES (%s,%s,%s,%s)",
        (election_id, json.dumps(results), json.dumps(published_hashes), now_utc())
    )

    return jsonify(results)

# === Paste any additional routes from your original app.py below this line ===
# (Example: admin_create_election, vote submission endpoints, etc.)
# Make sure they remain below, unchanged, unless you want additional edits.

if __name__ == "__main__":
    # Dev only (production runs via gunicorn)
    app.run(host="0.0.0.0", port=5000)