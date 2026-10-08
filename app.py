"""System A (password) and System B (passkey/WebAuthn) on one FastAPI server.
WebAuthn verification is implemented by hand (ES256, attestation 'none') so each
cryptographic step from the slides is visible."""
import base64, hashlib, hmac, io, json, os, secrets, sqlite3, struct
import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

RP_ID = os.getenv("RP_ID", "localhost")
ORIGIN = os.getenv("ORIGIN", "http://localhost:8000")  # use https:// in production
MAX_FAILS = 5

db = sqlite3.connect(os.getenv("DB", "auth.db"), check_same_thread=False)
db.executescript("""
create table if not exists pw(user text primary key, salt blob, hash blob);
create table if not exists cred(id text primary key, user text, pub blob, counter int);""")

app = FastAPI(title="Passwords vs Passkeys")
challenges, sessions, fails = {}, {}, {}

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
sha = lambda b: hashlib.sha256(b).digest()
pw_hash = lambda p, salt: hashlib.pbkdf2_hmac("sha256", p.encode(), salt, 100_000)

def new_session(user):
    t = secrets.token_urlsafe(32); sessions[t] = user; return {"token": t, "user": user}

# ---------- System A: password ----------
@app.post("/pw/register")
def pw_register(d: dict):
    salt = os.urandom(16)
    try:
        db.execute("insert into pw values(?,?,?)", (d["user"], salt, pw_hash(d["password"], salt)))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "user exists")
    return {"ok": True}

@app.post("/pw/login")
def pw_login(d: dict):
    u = d["user"]
    if fails.get(u, 0) >= MAX_FAILS:
        raise HTTPException(429, "account locked (brute-force protection)")
    row = db.execute("select salt,hash from pw where user=?", (u,)).fetchone()
    if not row or not hmac.compare_digest(row[1], pw_hash(d["password"], row[0])):
        fails[u] = fails.get(u, 0) + 1
        raise HTTPException(401, "invalid credentials")
    fails[u] = 0
    return new_session(u)

# ---------- System B: passkey (WebAuthn) ----------
def check_client_data(raw: str, typ: str, user: str):
    cd = json.loads(unb64u(raw))
    expected = challenges.pop((user, typ), None)            # one-time use -> replay resistance
    if cd.get("type") != typ or expected is None or not hmac.compare_digest(cd.get("challenge", ""), expected):
        raise HTTPException(400, "bad or reused challenge")
    if cd.get("origin") != ORIGIN:                           # origin binding -> phishing resistance
        raise HTTPException(400, f"origin mismatch: {cd.get('origin')}")
    return unb64u(raw)

def check_auth_data(ad: bytes, need_uv=True):
    if ad[:32] != sha(RP_ID.encode()):
        raise HTTPException(400, "rpIdHash mismatch")
    flags = ad[32]
    if not flags & 0x01: raise HTTPException(400, "user presence missing")
    if need_uv and not flags & 0x04: raise HTTPException(400, "user verification missing")
    return flags, struct.unpack(">I", ad[33:37])[0]

@app.post("/pk/register/options")
def pk_reg_options(d: dict):
    c = b64u(os.urandom(32)); challenges[(d["user"], "webauthn.create")] = c
    return {"challenge": c, "rp": {"id": RP_ID, "name": "Demo RP"},
            "user": {"id": b64u(d["user"].encode()), "name": d["user"], "displayName": d["user"]},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"userVerification": "required", "residentKey": "preferred"},
            "attestation": "none"}

@app.post("/pk/register/verify")
def pk_reg_verify(d: dict):
    check_client_data(d["clientDataJSON"], "webauthn.create", d["user"])
    ad = cbor2.loads(unb64u(d["attestationObject"]))["authData"]
    flags, counter = check_auth_data(ad)
    if not flags & 0x40: raise HTTPException(400, "no attested credential data")
    n = struct.unpack(">H", ad[53:55])[0]; cid = ad[55:55 + n]
    key = cbor2.CBORDecoder(io.BytesIO(ad[55 + n:])).decode()
    if key.get(3) != -7 or key.get(-1) != 1: raise HTTPException(400, "only ES256/P-256 supported")
    db.execute("insert into cred values(?,?,?,?)", (b64u(cid), d["user"], key[-2] + key[-3], counter))
    return {"ok": True, "credentialId": b64u(cid)}      # only the PUBLIC key is stored

@app.post("/pk/login/options")
def pk_login_options(d: dict):
    ids = [r[0] for r in db.execute("select id from cred where user=?", (d["user"],))]
    c = b64u(os.urandom(32)); challenges[(d["user"], "webauthn.get")] = c
    return {"challenge": c, "rpId": RP_ID, "userVerification": "required",
            "allowCredentials": [{"type": "public-key", "id": i} for i in ids]}

@app.post("/pk/login/verify")
def pk_login_verify(d: dict):
    u = d["user"]
    cd_raw = check_client_data(d["clientDataJSON"], "webauthn.get", u)
    row = db.execute("select pub,counter from cred where id=? and user=?", (d["id"], u)).fetchone()
    if not row: raise HTTPException(401, "unknown credential")
    ad = unb64u(d["authenticatorData"]); _, counter = check_auth_data(ad)
    if (counter or row[1]) and counter <= row[1]:
        raise HTTPException(401, "sign counter did not increase (cloned authenticator?)")
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(row[0][:32], "big"),
                                        int.from_bytes(row[0][32:], "big"), ec.SECP256R1()).public_key()
    try:
        pub.verify(unb64u(d["signature"]), ad + sha(cd_raw), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise HTTPException(401, "signature verification failed")
    db.execute("update cred set counter=? where id=?", (counter, d["id"]))
    return new_session(u)

@app.get("/me")
def me(token: str):
    if token not in sessions: raise HTTPException(401, "no session")
    return {"user": sessions[token]}

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
if os.path.isdir(STATIC):
    app.mount("/", StaticFiles(directory=STATIC, html=True))
else:  # flat download: index.html sits next to app.py
    from fastapi.responses import FileResponse
    @app.get("/")
    def index():
        return FileResponse(os.path.join(HERE, "index.html"))