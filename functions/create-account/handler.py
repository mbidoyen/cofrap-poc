import base64
import io
import json
import secrets
import string
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


def generate_password(length=24):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    specials = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    password = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(specials),
    ]
    all_chars = upper + lower + digits + specials
    password += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def to_qr_base64(data):
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def handle(event, context):
    try:
        payload = json.loads(event.body)
        username = payload.get("username", "").strip()

        if not username:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "username is required"}),
            }

        fernet_key = read_secret("fernet-key").encode()

        plain_password = generate_password(24)
        encrypted_password = encrypt(plain_password, fernet_key)
        qr_password = to_qr_base64(plain_password)

        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name=username, issuer_name="COFRAP")
        encrypted_mfa = encrypt(totp_secret, fernet_key)
        qr_totp = to_qr_base64(uri)

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
                        INSERT INTO users (username, password, mfa, gendate, expired)
                        VALUES (%s, %s, %s, %s, 0)
                        ON CONFLICT (username) DO UPDATE
                        SET password = EXCLUDED.password,
                            mfa      = EXCLUDED.mfa,
                            gendate  = EXCLUDED.gendate,
                            expired  = 0
                        """,
                        (username, encrypted_password, encrypted_mfa, int(time.time())),
                    )
        finally:
            conn.close()

        return {
            "statusCode": 201,
            "body": json.dumps({
                "username": username,
                "qrcode_password_base64": qr_password,
                "qrcode_totp_base64": qr_totp,
                "message": "Account created. Scan QR 1 for password, QR 2 for 2FA."
            }),
            "headers": {"Content-Type": "application/json"},
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
