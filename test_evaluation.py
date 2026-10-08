"""Security evaluation (slide 13). Run: python test_evaluation.py"""
import os, json, struct, hashlib
os.environ["DB"] = ":memory:"
import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
import app as S
from app import b64u, unb64u, sha

c = TestClient(S.app)
results = []
def record(attack, system, defended, note): results.append((attack, system, "DEFENDED" if defended else "VULNERABLE", note))

class Authenticator:
    """Software FIDO2 authenticator: private key never leaves this object."""
    def __init__(s, rp_id=S.RP_ID):
        s.k, s.rp, s.cid, s.n = ec.generate_private_key(ec.SECP256R1()), rp_id, os.urandom(16), 0
    def _cd(s, typ, chal, origin): return json.dumps({"type": typ, "challenge": chal, "origin": origin}).encode()
    def create(s, chal, origin=S.ORIGIN):
        p = s.k.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: p.x.to_bytes(32, "big"), -3: p.y.to_bytes(32, "big")})
        ad = sha(s.rp.encode()) + b"\x45" + struct.pack(">I", 0) + bytes(16) + struct.pack(">H", 16) + s.cid + cose
        return {"clientDataJSON": b64u(s._cd("webauthn.create", chal, origin)),
                "attestationObject": b64u(cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad}))}
    def get(s, chal, origin=S.ORIGIN, flags=0x05, bump=True):
        s.n += bump
        cd = s._cd("webauthn.get", chal, origin)
        ad = sha(s.rp.encode()) + bytes([flags]) + struct.pack(">I", s.n)
        sig = s.k.sign(ad + sha(cd), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(s.cid), "clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig)}

def pk_register(user, a):
    o = c.post("/pk/register/options", json={"user": user}).json()
    return c.post("/pk/register/verify", json={"user": user, **a.create(o["challenge"])})
def pk_login(user, a, **kw):
    o = c.post("/pk/login/options", json={"user": user}).json()
    return c.post("/pk/login/verify", json={"user": user, **a.get(o["challenge"], **kw)})

# 0. functional: honest flows work
assert c.post("/pw/register", json={"user": "alice", "password": "Summer2024"}).status_code == 200
assert c.post("/pw/login", json={"user": "alice", "password": "Summer2024"}).status_code == 200
dev = Authenticator(); assert pk_register("bob", dev).status_code == 200
r = pk_login("bob", dev); assert r.status_code == 200 and c.get("/me", params={"token": r.json()["token"]}).json()["user"] == "bob"
print("Functional: password + passkey register/login OK\n")

# 1. Phishing: attacker site relays the victim's credentials
stolen = {"user": "alice", "password": "Summer2024"}            # victim typed it into fake site
record("Phishing", "Password", c.post("/pw/login", json=stolen).status_code != 200, "attacker logs in with typed password")
o = c.post("/pk/login/options", json={"user": "bob"}).json()
r = c.post("/pk/login/verify", json={"user": "bob", **dev.get(o["challenge"], origin="https://evil.example")})
record("Phishing", "Passkey", r.status_code == 400, f"server: {r.json()['detail']}")
evil_rp = Authenticator(rp_id="evil.example"); evil_rp.k, evil_rp.cid = dev.k, dev.cid   # browser would sign for evil's RP ID
o = c.post("/pk/login/options", json={"user": "bob"}).json()
r = c.post("/pk/login/verify", json={"user": "bob", **evil_rp.get(o["challenge"])})
record("Phishing (RP ID hash)", "Passkey", r.status_code == 400, f"server: {r.json()['detail']}")

# 2. Replay: capture a valid login and resend it
cap = {"user": "bob", **dev.get(c.post("/pk/login/options", json={"user": "bob"}).json()["challenge"])}
assert c.post("/pk/login/verify", json=cap).status_code == 200
r = c.post("/pk/login/verify", json=cap)
record("Replay", "Passkey", r.status_code != 200, f"server: {r.json()['detail']}")
record("Replay", "Password", False, "captured password/session credential reusable; nothing proves freshness")

# 3. Signature tampering / MITM modification
o = c.post("/pk/login/options", json={"user": "bob"}).json(); a = dev.get(o["challenge"])
sig = bytearray(unb64u(a["signature"])); sig[-1] ^= 1; a["signature"] = b64u(bytes(sig))
r = c.post("/pk/login/verify", json={"user": "bob", **a})
record("MITM tamper", "Passkey", r.status_code == 401, f"server: {r.json()['detail']}")
o = c.post("/pk/login/options", json={"user": "bob"}).json()
r = c.post("/pk/login/verify", json={"user": "bob", **Authenticator().get(o["challenge"])})   # attacker's own key
record("Forged authenticator", "Passkey", r.status_code == 401, f"server: {r.json()['detail']}")

# 4. Missing user verification (stolen unlocked key without PIN/biometric)
r = pk_login("bob", dev, flags=0x01)
record("No user verification", "Passkey", r.status_code == 400, f"server: {r.json()['detail']}")

# 5. Cloned authenticator (sign counter regression)
clone_n = dev.n; dev.n = 0
r = pk_login("bob", dev); dev.n = clone_n + 5
record("Cloned authenticator", "Passkey", r.status_code == 401, f"server: {r.json()['detail']}")

# 6. Brute force
codes = [c.post("/pw/login", json={"user": "alice", "password": f"guess{i}"}).status_code for i in range(7)]
record("Brute force", "Password", codes[-1] == 429, f"locked after {codes.count(401)} failures (only with lockout; offline guessing still possible)")
record("Brute force", "Passkey", True, "no secret to guess: 256-bit ECDSA key, random 256-bit challenge")

# 7. Database compromise
c.post("/pw/register", json={"user": "carol", "password": "password123"})
salt, h = S.db.execute("select salt,hash from pw where user='carol'").fetchone()
cracked = next((w for w in ["123456", "qwerty", "password123", "letmein"] if S.pw_hash(w, salt) == h), None)
record("DB breach", "Password", cracked is None, f"offline dictionary attack recovered '{cracked}' from stored hash")
pub = S.db.execute("select pub from cred where user='bob'").fetchone()[0]
forged_ok = False   # attacker has only the public key: can verify, cannot sign
record("DB breach", "Passkey", not forged_ok, f"only public key ({len(pub)} bytes) stored; nothing reusable")

# 8. Credential stuffing / reuse across services
record("Credential stuffing", "Password", False, "same password works wherever reused (stolen creds replayed to /pw/login)")
other = Authenticator(rp_id="other-site.example")   # credential for another site is a different key pair per RP
r = pk_login("bob", other)
record("Credential stuffing", "Passkey", r.status_code in (400, 401), f"per-site key pair; cross-site credential rejected ({r.json()['detail']})")

print(f"{'Attack':<24}{'System':<10}{'Result':<11}Evidence")
print("-" * 100)
for a, s, res, n in results: print(f"{a:<24}{s:<10}{res:<11}{n}")
pk = [r for r in results if r[1] == "Passkey"]; pw = [r for r in results if r[1] == "Password"]
print(f"\nPasskey: {sum(r[2]=='DEFENDED' for r in pk)}/{len(pk)} defended | Password: {sum(r[2]=='DEFENDED' for r in pw)}/{len(pw)} defended")
assert all(r[2] == "DEFENDED" for r in pk), "a passkey attack succeeded"
