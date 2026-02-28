import os
import json
import base64
import hashlib
import datetime as dt
from pathlib import Path

import mysql.connector
from flask import Flask, request, jsonify, abort
from dotenv import load_dotenv

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

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
        host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, autocommit=True
    )

def now_utc():
    return dt.datetime.utcnow().replace(microsecond=0)

def parse_iso(s: str) -> dt.datetime:
    s = s.strip().replace("Z", "")
    return dt.datetime.fromisoformat(s)

def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def require_admin():
    token = request.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        abort(403, description="Admin token missing/invalid")

# =========================
# Credential signer keys (MVP: server signs token)
# =========================
CRED_PRIV_PATH = Path(KEYS_DIR) / "credential_signer_private.pem"
CRED_PUB_PATH  = Path(KEYS_DIR) / "credential_signer_public.pem"

def ensure_credential_signer_keys():
    if CRED_PRIV_PATH.exists() and CRED_PUB_PATH.exists():
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    CRED_PRIV_PATH.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    CRED_PUB_PATH.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(CRED_PRIV_PATH, 0o600)

def load_cred_private():
    ensure_credential_signer_keys()
    return serialization.load_pem_private_key(CRED_PRIV_PATH.read_bytes(), password=None)

def load_cred_public():
    ensure_credential_signer_keys()
    return serialization.load_pem_public_key(CRED_PUB_PATH.read_bytes())

# =========================
# Election keypair
# =========================
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

    return pub_pem.decode("utf-8"), str(priv_path)

# =========================
# Routes
# =========================
@app.get("/")
def health():
    return jsonify({"status": "ok", "service": "Electronic Voting API"})

# ---- Users ----
@app.post("/register")
def register():
    """
    Body:
    {
      "national_id": "1234567890",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----..."
    }
    """
    data = request.get_json(force=True)
    national_id = (data.get("national_id") or "").strip()
    public_key_pem = (data.get("public_key_pem") or "").strip()

    if len(national_id) < 3:
        abort(400, description="national_id invalid")
    if "BEGIN PUBLIC KEY" not in public_key_pem:
        abort(400, description="public_key_pem invalid")

    nid_hash_hex = hashlib.sha256(national_id.encode("utf-8")).hexdigest()
    district = "A" if int(nid_hash_hex, 16) % 2 == 0 else "B"

    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO users (national_id_hash, public_key_pem, district, eligible, created_at)
            VALUES (%s,%s,%s,1,%s)
            """,
            (nid_hash_hex, public_key_pem, district, now_utc()),
        )
    except mysql.connector.errors.IntegrityError:
        abort(409, description="User already registered")

    return jsonify({"message": "registered", "district": district})

# ---- Credential issuance (MVP: server signs token; not blind) ----
@app.get("/credential/public-key")
def credential_public_key():
    ensure_credential_signer_keys()
    return jsonify({"credential_signer_public_key_pem": CRED_PUB_PATH.read_text()})

@app.post("/credential/issue")
def credential_issue():
    """
    Body:
    {
      "national_id": "...",
      "token_b64": "base64(random_bytes)"
    }
    """
    data = request.get_json(force=True)
    national_id = (data.get("national_id") or "").strip()
    token_b64 = (data.get("token_b64") or "").strip()

    if not national_id or not token_b64:
        abort(400, description="missing fields")

    try:
        token = base64.b64decode(token_b64, validate=True)
    except Exception:
        abort(400, description="token_b64 must be valid base64")
    if len(token) < 16:
        abort(400, description="token too short")

    nid_hash_hex = hashlib.sha256(national_id.encode("utf-8")).hexdigest()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT eligible FROM users WHERE national_id_hash=%s", (nid_hash_hex,))
    user = cur.fetchone()
    if not user or int(user["eligible"]) != 1:
        abort(403, description="not eligible")

    priv = load_cred_private()
    sig = priv.sign(
        token,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return jsonify({"signature_hex": sig.hex()})

# ---- Admin create election ----
@app.post("/admin/elections")
def admin_create_election():
    """
    Header: X-Admin-Token
    Body:
    {
      "title": "Test Election",
      "scope": "global" | "district",
      "district": "A" | "B" (required if scope=district),
      "filing_open": "2026-03-01T00:00:00",
      "filing_close": "...",
      "ballot_open": "...",
      "ballot_close": "..."
    }
    """
    require_admin()
    data = request.get_json(force=True)

    title = (data.get("title") or "").strip()
    scope = (data.get("scope") or "").strip()
    district = data.get("district")
    if district is not None:
        district = str(district).strip().upper()

    if not title or scope not in ("global", "district"):
        abort(400, description="title/scope invalid")
    if scope == "district" and district not in ("A", "B"):
        abort(400, description="district must be A or B")

    try:
        filing_open = parse_iso(data["filing_open"])
        filing_close = parse_iso(data["filing_close"])
        ballot_open = parse_iso(data["ballot_open"])
        ballot_close = parse_iso(data["ballot_close"])
    except Exception:
        abort(400, description="bad datetime. Use ISO like 2026-03-01T00:00:00")

    if not (filing_open < filing_close <= ballot_open < ballot_close):
        abort(400, description="dates must satisfy: filing_open < filing_close <= ballot_open < ballot_close")

    conn = db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO elections
          (title, scope, district, filing_open, filing_close, ballot_open, ballot_close,
           public_key_pem, private_key_path, status, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,'','', 'open', %s)
        """,
        (title, scope, district, filing_open, filing_close, ballot_open, ballot_close, now_utc()),
    )
    election_id = cur.lastrowid

    pub_pem, priv_path = generate_election_keypair(election_id)
    cur.execute(
        "UPDATE elections SET public_key_pem=%s, private_key_path=%s WHERE id=%s",
        (pub_pem, priv_path, election_id),
    )

    return jsonify({"message": "election created", "election_id": election_id})

# ---- Elections public ----
@app.get("/elections")
def list_elections():
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, title, scope, district, filing_open, filing_close, ballot_open, ballot_close, status
        FROM elections
        ORDER BY id DESC
        """
    )
    return jsonify({"elections": cur.fetchall()})

@app.get("/elections/<int:election_id>")
def get_election(election_id: int):
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, title, scope, district, filing_open, filing_close, ballot_open, ballot_close, status
        FROM elections WHERE id=%s
        """,
        (election_id,),
    )
    e = cur.fetchone()
    if not e:
        abort(404, description="election not found")

    cur.execute(
        "SELECT id, display_name FROM candidates WHERE election_id=%s ORDER BY id ASC",
        (election_id,),
    )
    candidates = cur.fetchall()

    return jsonify({"election": e, "candidates": candidates})

@app.get("/elections/<int:election_id>/public-key")
def election_public_key(election_id: int):
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT public_key_pem FROM elections WHERE id=%s", (election_id,))
    row = cur.fetchone()
    if not row:
        abort(404, description="election not found")
    return jsonify({"public_key_pem": row["public_key_pem"]})

# ---- Candidate filing ----
@app.post("/elections/<int:election_id>/candidates")
def file_candidate(election_id: int):
    """
    Body:
    {
      "national_id": "...",
      "display_name": "Alice"
    }
    """
    data = request.get_json(force=True)
    national_id = (data.get("national_id") or "").strip()
    display_name = (data.get("display_name") or "").strip()
    if not national_id or not display_name:
        abort(400, description="missing fields")

    nid_hash_hex = hashlib.sha256(national_id.encode("utf-8")).hexdigest()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT id, eligible FROM users WHERE national_id_hash=%s", (nid_hash_hex,))
    user = cur.fetchone()
    if not user or int(user["eligible"]) != 1:
        abort(403, description="not eligible")

    cur.execute(
        "SELECT filing_open, filing_close, status FROM elections WHERE id=%s",
        (election_id,),
    )
    e = cur.fetchone()
    if not e:
        abort(404, description="election not found")
    if e["status"] != "open":
        abort(400, description="election is not open")

    t = now_utc()
    if not (e["filing_open"] <= t <= e["filing_close"]):
        abort(400, description="candidate filing is closed")

    cur2 = conn.cursor()
    try:
        cur2.execute(
            """
            INSERT INTO candidates (election_id, user_id, display_name, created_at)
            VALUES (%s,%s,%s,%s)
            """,
            (election_id, user["id"], display_name, now_utc()),
        )
    except mysql.connector.errors.IntegrityError:
        abort(409, description="already filed")

    return jsonify({"message": "filed", "candidate_name": display_name})

# ---- Vote submit (ciphertext opaque for now) ----
@app.post("/elections/<int:election_id>/vote")
def submit_vote(election_id: int):
    """
    Body:
    {
      "token_b64": "...",
      "signature_hex": "...",
      "ciphertext_b64": "...",
      "ballot_hash_hex": "..."  (sha256)
    }
    """
    data = request.get_json(force=True)
    token_b64 = (data.get("token_b64") or "").strip()
    signature_hex = (data.get("signature_hex") or "").strip()
    ciphertext_b64 = (data.get("ciphertext_b64") or "").strip()
    ballot_hash_hex = (data.get("ballot_hash_hex") or "").strip()

    if not token_b64 or not signature_hex or not ciphertext_b64 or not ballot_hash_hex:
        abort(400, description="missing fields")

    try:
        token = base64.b64decode(token_b64, validate=True)
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        ballot_hash = bytes.fromhex(ballot_hash_hex)
        signature = bytes.fromhex(signature_hex)
    except Exception:
        abort(400, description="bad encoding (base64/hex)")

    if len(ballot_hash) != 32:
        abort(400, description="ballot_hash must be 32 bytes")

    # Verify credential signature
    pub = load_cred_public()
    try:
        pub.verify(
            signature,
            token,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except Exception:
        abort(400, description="invalid credential signature")

    credential_hash = sha256_bytes(token)

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        "SELECT ballot_open, ballot_close, status FROM elections WHERE id=%s",
        (election_id,),
    )
    e = cur.fetchone()
    if not e:
        abort(404, description="election not found")
    if e["status"] != "open":
        abort(400, description="election not open")

    t = now_utc()
    if not (e["ballot_open"] <= t <= e["ballot_close"]):
        abort(400, description="voting is closed")

    # Insert vote (UNIQUE prevents double vote)
    cur2 = conn.cursor()
    try:
        cur2.execute(
            """
            INSERT INTO votes (election_id, credential_hash, ciphertext, ballot_hash, submitted_at)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (election_id, credential_hash, ciphertext, ballot_hash, now_utc()),
        )
    except mysql.connector.errors.IntegrityError:
        abort(409, description="already voted (credential reused)")

    return jsonify({"message": "vote accepted"})

# ---- Close election & publish results (MVP: publish hashes + count) ----
@app.post("/admin/elections/<int:election_id>/close")
def admin_close_election(election_id: int):
    require_admin()

    conn = db_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT status FROM elections WHERE id=%s", (election_id,))
    e = cur.fetchone()
    if not e:
        abort(404, description="election not found")
    if e["status"] == "closed":
        return jsonify({"message": "already closed"})

    cur.execute(
        "SELECT HEX(ballot_hash) AS ballot_hash_hex FROM votes WHERE election_id=%s ORDER BY id ASC",
        (election_id,),
    )
    hashes_list = [r["ballot_hash_hex"].lower() for r in cur.fetchall()]

    results = {"total_votes": len(hashes_list), "note": "MVP: ciphertext stored; decrypt+tally next"}

    cur2 = conn.cursor()
    cur2.execute("UPDATE elections SET status='closed' WHERE id=%s", (election_id,))
    cur2.execute(
        """
        INSERT INTO results (election_id, results_json, published_hashes, published_at)
        VALUES (%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
          results_json=VALUES(results_json),
          published_hashes=VALUES(published_hashes),
          published_at=VALUES(published_at)
        """,
        (election_id, json.dumps(results), json.dumps(hashes_list), now_utc()),
    )

    return jsonify({"message": "closed", "results": results, "ballot_hashes": hashes_list})

@app.get("/elections/<int:election_id>/results")
def get_results(election_id: int):
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT results_json, published_hashes, published_at FROM results WHERE election_id=%s", (election_id,))
    r = cur.fetchone()
    if not r:
        abort(404, description="results not published")

    return jsonify({
        "results": json.loads(r["results_json"]),
        "ballot_hashes": json.loads(r["published_hashes"]),
        "published_at": r["published_at"].isoformat() if hasattr(r["published_at"], "isoformat") else str(r["published_at"]),
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)