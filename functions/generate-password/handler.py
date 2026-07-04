"""
generate-password : génère un mot de passe complexe de 24 caractères,
le chiffre avec Fernet, le stocke en base, et retourne un QR code.
"""

import json
import secrets
import string
import time

from _shared import read_secret, encrypt, to_qr_base64, db_connect


def generate_password(length: int = 24) -> str:
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


def store_user(username: str, encrypted_password: str) -> None:
    conn = db_connect()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (username, password, mfa, gendate, expired)
                    VALUES (%s, %s, %s, %s, 0)
                    ON CONFLICT (username) DO UPDATE
                    SET password = EXCLUDED.password,
                        gendate  = EXCLUDED.gendate,
                        expired  = 0
                    """,
                    (username, encrypted_password, "", int(time.time())),
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

        plain_password = generate_password(24)
        fernet_key = read_secret("fernet-key").encode()
        encrypted = encrypt(plain_password, fernet_key)
        store_user(username, encrypted)
        qr_b64 = to_qr_base64(plain_password)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "username": username,
                "qrcode_base64": qr_b64,
                "message": "Password generated and stored. Scan the QR code to retrieve it."
            }),
            "headers": {"Content-Type": "application/json"},
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
