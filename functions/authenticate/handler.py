"""
authenticate : verifie login + mot de passe + code TOTP.
Si les identifiants ont plus de 6 mois, marque le compte comme expire
et demande au frontend de relancer le processus de creation.
"""

import json
import time

import psycopg2
import pyotp
from cryptography.fernet import Fernet


# Duree de validite des identifiants en secondes (6 mois ~ 180 jours)
EXPIRATION_SECONDS = 180 * 24 * 3600


def read_secret(name):
    with open(f"/var/openfaas/secrets/{name}", "r") as f:
        return f.read().strip()


def decrypt(token, key):
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()


def get_user(username):
    """Retourne dict {password, mfa, gendate, expired} ou None si inexistant."""
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
                    "SELECT password, mfa, gendate, expired FROM users WHERE username = %s",
                    (username,),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                return {
                    "password": row[0],
                    "mfa": row[1],
                    "gendate": row[2],
                    "expired": row[3],
                }
    finally:
        conn.close()


def mark_expired(username):
    """Marque l'utilisateur comme expire (expired = 1)."""
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
                    "UPDATE users SET expired = 1 WHERE username = %s",
                    (username,),
                )
    finally:
        conn.close()


def handle(event, context):
    try:
        payload = json.loads(event.body)
        username = payload.get("username", "").strip()
        password = payload.get("password", "")
        totp_code = payload.get("totp_code", "").strip()

        if not username or not password or not totp_code:
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "error": "username, password and totp_code are required"
                }),
            }

        user = get_user(username)

        if user is None:
            return {
                "statusCode": 404,
                "body": json.dumps({
                    "error": f"user '{username}' not found",
                    "action": "create_account"
                }),
            }

        # Verification expiration
        now = int(time.time())
        age = now - user["gendate"]

        if user["expired"] == 1 or age > EXPIRATION_SECONDS:
            mark_expired(username)
            return {
                "statusCode": 403,
                "body": json.dumps({
                    "error": "credentials expired (older than 6 months)",
                    "action": "renew_credentials"
                }),
            }

        # Dechiffrement
        fernet_key = read_secret("fernet-key").encode()

        try:
            stored_password = decrypt(user["password"], fernet_key)
            totp_secret = decrypt(user["mfa"], fernet_key)
        except Exception:
            return {
                "statusCode": 500,
                "body": json.dumps({"error": "decryption failed (corrupted data or wrong key)"}),
            }

        # Verification mot de passe
        if password != stored_password:
            return {
                "statusCode": 401,
                "body": json.dumps({"error": "invalid password"}),
            }

        # Verification code TOTP
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            return {
                "statusCode": 401,
                "body": json.dumps({"error": "invalid TOTP code"}),
            }

        # Tout est OK
        return {
            "statusCode": 200,
            "body": json.dumps({
                "username": username,
                "authenticated": True,
                "message": "Authentication successful"
            }),
            "headers": {"Content-Type": "application/json"},
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
