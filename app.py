import json
import hmac
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, request, jsonify, make_response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

app = Flask(__name__)

# =========================
# Config
# =========================
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
SIG_DIR = BASE_DIR / "signatures"
KEY_DIR = BASE_DIR / "keys"

UPLOAD_DIR.mkdir(exist_ok=True)
SIG_DIR.mkdir(exist_ok=True)
KEY_DIR.mkdir(exist_ok=True)

# Secret key for HMAC: must stay on the server only
SERVER_HMAC_SECRET = b"super-secret-server-key-change-this"

# Demo users
USERS = {
    "alice": {"password": "1234", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}

PRIVATE_KEY_PATH = KEY_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "public_key.pem"


# =========================
# Helpers: Base64
# =========================
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


# =========================
# Helpers: Cookie + HMAC
# =========================
def sign_cookie_payload(payload: dict) -> str:
    payload_bytes = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True
    ).encode("utf-8")

    mac = hmac.new(SERVER_HMAC_SECRET, payload_bytes, hashlib.sha256).digest()
    return b64e(mac)


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def verify_cookie(payload_b64: str, mac_b64: str):
    try:
        payload_json = b64d(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)
    except Exception:
        return False, None, "Invalid payload encoding"

    expected_mac = sign_cookie_payload(payload)
    if not constant_time_compare(expected_mac, mac_b64):
        return False, None, "MAC verification failed (cookie tampering detected)"

    try:
        exp = datetime.fromisoformat(payload["exp"])
        if datetime.now(timezone.utc) > exp:
            return False, None, "Cookie expired"
    except Exception:
        return False, None, "Invalid expiration format"

    return True, payload, "Cookie valid"


def build_cookie(username: str, role: str, expires_minutes: int = 15):
    payload = {
        "username": username,
        "role": role,
        "exp": (datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)).isoformat(),
    }

    payload_json = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True
    ).encode("utf-8")

    payload_b64 = b64e(payload_json)
    mac_b64 = sign_cookie_payload(payload)

    return payload_b64, mac_b64, payload


# =========================
# Helpers: RSA Signatures
# =========================
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    return private_pem.decode("utf-8"), public_pem.decode("utf-8")


def load_private_key():
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError("Private key not found. Generate keys first.")

    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )


def load_public_key():
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError("Public key not found. Generate keys first.")

    return serialization.load_pem_public_key(
        PUBLIC_KEY_PATH.read_bytes()
    )


def sign_file_bytes(file_bytes: bytes) -> bytes:
    private_key = load_private_key()

    signature = private_key.sign(
        file_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_file_signature(file_bytes: bytes, signature: bytes) -> bool:
    public_key = load_public_key()

    try:
        public_key.verify(
            signature,
            file_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# =========================
# Routes: Home
# =========================
@app.route("/")
def home():
    return jsonify({
        "message": "Secure Cookies + Digital Signature Demo",
        "routes": [
            "POST /login",
            "GET /protected",
            "POST /generate-keys",
            "POST /sign-file",
            "POST /verify-file",
            "POST /attack/key-substitution"
        ]
    })


# =========================
# Routes: Part A
# =========================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if username not in USERS or USERS[username]["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    role = USERS[username]["role"]
    payload_b64, mac_b64, payload = build_cookie(username, role)

    response = make_response(jsonify({
        "message": "Login successful",
        "cookie_payload_for_demo": payload_b64,
        "cookie_mac_for_demo": mac_b64,
        "decoded_payload": payload,
        "note": "Normally the browser stores cookies automatically. These values are shown for testing/tampering demo."
    }))

    # For demo only. In production, usually httponly should be True.
    response.set_cookie("auth_payload", payload_b64, httponly=False, samesite="Lax")
    response.set_cookie("auth_mac", mac_b64, httponly=False, samesite="Lax")

    return response


@app.route("/protected", methods=["GET"])
def protected():
    payload_b64 = request.cookies.get("auth_payload")
    mac_b64 = request.cookies.get("auth_mac")

    if not payload_b64 or not mac_b64:
        return jsonify({"error": "Missing authentication cookie"}), 401

    valid, payload, reason = verify_cookie(payload_b64, mac_b64)
    if not valid:
        return jsonify({"error": reason}), 403

    return jsonify({
        "message": "Access granted to protected resource",
        "user": payload["username"],
        "role": payload["role"],
        "expires": payload["exp"],
    })


# =========================
# Routes: Part B
# =========================
@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    private_pem, public_pem = generate_rsa_keypair()

    return jsonify({
        "message": "RSA key pair generated successfully",
        "private_key_path": str(PRIVATE_KEY_PATH),
        "public_key_path": str(PUBLIC_KEY_PATH),
        "public_key_preview": public_pem[:120] + "..."
    })


@app.route("/sign-file", methods=["POST"])
def sign_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    file_bytes = f.read()

    if not file_bytes:
        return jsonify({"error": "Empty file"}), 400

    file_path = UPLOAD_DIR / f.filename
    file_path.write_bytes(file_bytes)

    signature = sign_file_bytes(file_bytes)
    sig_path = SIG_DIR / f"{f.filename}.sig"
    sig_path.write_bytes(signature)

    return jsonify({
        "message": "File signed successfully",
        "file_path": str(file_path),
        "signature_path": str(sig_path),
        "signature_base64": b64e(signature),
        "public_key_path": str(PUBLIC_KEY_PATH),
    })


@app.route("/verify-file", methods=["POST"])
def verify_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    signature_b64 = request.form.get("signature_base64")
    if not signature_b64:
        return jsonify({"error": "Missing signature_base64"}), 400

    try:
        signature = b64d(signature_b64)
    except Exception:
        return jsonify({"error": "Invalid signature encoding"}), 400

    f = request.files["file"]
    file_bytes = f.read()

    ok = verify_file_signature(file_bytes, signature)

    if ok:
        return jsonify({
            "message": "Signature verification SUCCESS",
            "valid": True
        })

    return jsonify({
        "message": "Signature verification FAILED (file modified or wrong signature/public key)",
        "valid": False
    }), 400


# =========================
# Bonus: Key Substitution Attack
# =========================
@app.route("/attack/key-substitution", methods=["POST"])
def key_substitution_attack():
    """
    Demo only:
    The attacker creates his own key pair, signs fake data with his private key,
    then verification succeeds when the system incorrectly trusts the attacker's public key.
    """

    # 1) attacker creates his own key pair
    attacker_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    attacker_public = attacker_private.public_key()

    # 2) fake message/file created by attacker
    fake_message = b"This is a fake file created by attacker"

    # 3) attacker signs it with his private key
    fake_signature = attacker_private.sign(
        fake_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # 4) system verifies using the WRONG public key (attacker's public key)
    try:
        attacker_public.verify(
            fake_signature,
            fake_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        result = "Verification SUCCESS (but this is an attack!)"
    except Exception:
        result = "Verification FAILED"

    return jsonify({
        "message": "Key Substitution Attack Demo",
        "result": result,
        "fake_message": fake_message.decode("utf-8"),
        "explanation": [
            "Attacker generated his own key pair.",
            "Attacker signed fake data using his private key.",
            "Verification succeeded because the wrong public key was trusted."
        ],
        "prevention": "Use trusted certificates / PKI / certificate authorities to bind public keys to identities."
    })


# =========================
# Run App
# =========================
if __name__ == "__main__":
    app.run(debug=True)