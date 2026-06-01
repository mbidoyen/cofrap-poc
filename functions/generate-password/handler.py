"""
generate-password : génère un mot de passe complexe de 24 caractères,
le chiffre avec Fernet, le stocke en base, et retourne un QR code.
"""

import base64
import io
import json
import secrets
import string
import time

import psycopg2
import qrcode
from cryptography.fernet import Fernet


# --- Helpers : lecture des secrets OpenFaaS ---

def read_secret(name: str) -> str:
    """Lit un secret monté par OpenFaaS dans /var/openfaas/secrets/."""
    with open(f"/var/openfaas/secrets/{name}", "r") as f:
        return f.read().strip()


# --- Génération du mot de passe ---

def generate_password(length: int = 24) -> str:
    """
    Génère un mot de passe de `length` caractères contenant
    au moins une majuscule, une minuscule, un chiffre, un caractère spécial.
    """
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    specials = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Au moins un caractère de chaque catégorie
    password = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(specials),
    ]
    # Compléter avec un mélange de tout
    all_chars = upper + lower + digits + specials
    password += [secrets.choice(all_chars) for _ in range(length - 4)]

    # Mélanger pour ne pas avoir le pattern "1 upper, 1 lower, ..." au début
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


# --- Génération du QR code en base64 ---

def password_to_qr_base64(password: str) -> str:
    """Génère un QR code à partir du mot de passe et le retourne en base64 PNG."""
    img = qrcode.make(password)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


# --- Chiffrement Fernet ---

def encrypt(plain: str, key: bytes) -> str:
    """Chiffre une chaîne avec Fernet et retourne la version base64."""
    f = Fernet(key)
    return f.encrypt(plain.encode()).decode()


# --- Persistance DB ---

def store_user(username: str, encrypted_password: str) -> None:
    """Insère ou met à jour l'utilisateur en base."""
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
                        gendate  = EXCLUDED.gendate,
                        expired  = 0
                    """,
                    (username, encrypted_password, "", int(time.time())),
                )
    finally:
        conn.close()


# --- Handler OpenFaaS ---

def handle(event, context):
    """Point d'entrée OpenFaaS. event.body contient le payload."""
    try:
        payload = json.loads(event.body)
        username = payload.get("username", "").strip()

        if not username:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "username is required"}),
            }

        # 1. Générer le mot de passe
        plain_password = generate_password(24)

        # 2. Chiffrer
        fernet_key = read_secret("fernet-key").encode()
        encrypted = encrypt(plain_password, fernet_key)

        # 3. Stocker en base
        store_user(username, encrypted)

        # 4. Générer le QR code
        qr_b64 = password_to_qr_base64(plain_password)

        # 5. Retourner le résultat
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
