"""
generate-2fa : genere un secret TOTP, le chiffre, le stocke en base,
et retourne un QR code scannable par Google Authenticator / Authy.
"""

import base64
import io
import json
import time

import psycopg2
import pyotp
import qrcode
from cryptography.fernet import Fernet


def read_secret(name):
    with open(f"/var/openfaas/secrets/{name}", "r") as f:
        return f.read().strip()


def encrypt(plain, key):
    f = Fernet(key)
    return f.encrypt(plain.encode()).decode()


def totp_uri_to_qr_base64(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def user_exists(username):
    conn = psycopg2.connect(
        host=read_secret("db-host"),
        dbname=read_secret("db-name"),
        user=read_secret("db-user"),
        password=read_secret("db-password"),
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
                return cur.fetchone() is not None
    finally:
        conn.close()


def store_mfa(username, encrypted_mfa):
    conn = psycopg2.connect(
        host=read_secret("db-host"),
        dbname=read_secret("db-name"),
        user=read_secret("db-user"),
        password=read_secret("db-password"),
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users
                    SET mfa = %s,
                        gendate = %s,
                        expired = 0
                    WHERE username = %s
                    """,
                    (encrypted_mfa, int(time.time()), username),
                )
    finally:
        conn.close()


def handle(event, context):
    try:
        payload = json.loads(event.body)
        username = payload.get("username", "").strip()

        if not username:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "username is required"}),
            }

        if not user_exists(username):
            return {
                "statusCode": 404,
                "body": json.dumps({
                    "error": f"user '{username}' not found. Run generate-password first."
                }),
            }

        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name=username, issuer_name="COFRAP")

        qr_b64 = totp_uri_to_qr_base64(uri)

        fernet_key = read_secret("fernet-key").encode()
        encrypted = encrypt(totp_secret, fernet_key)

        store_mfa(username, encrypted)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "username": username,
                "qrcode_base64": qr_b64,
                "message": "2FA secret generated. Scan the QR code with Google Authenticator or Authy."
            }),
            "headers": {"Content-Type": "application/json"},
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
