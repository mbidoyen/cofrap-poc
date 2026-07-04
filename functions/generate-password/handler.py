"""
generate-password : génère un nouveau mot de passe pour un utilisateur existant,
le chiffre avec Fernet, le stocke en base, puis envoie le QR code par email.
Le QR code n'est JAMAIS renvoyé dans le corps de la réponse HTTP.
"""

import json
import secrets
import string
import time

from ._shared import read_secret, encrypt, to_qr_base64, db_connect, send_email


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


def get_user_email(username: str):
    """Retourne l'email de l'utilisateur, ou None s'il n'existe pas."""
    conn = db_connect()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        conn.close()


def store_password(username: str, encrypted_password: str) -> None:
    conn = db_connect()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users
                    SET password = %s,
                        gendate  = %s,
                        expired  = 0
                    WHERE username = %s
                    """,
                    (encrypted_password, int(time.time()), username),
                )
    finally:
        conn.close()


def _email_body(username: str) -> str:
    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#1E2761;">
      <h2>Nouveau mot de passe — {username}</h2>
      <p>Un nouveau mot de passe a été généré pour votre compte COFRAP.<br/>
      Scannez le QR code ci-dessous pour le récupérer.</p>
      <div style="text-align:center;padding:24px;">
        <img src="cid:qr_password" alt="QR mot de passe" width="220" height="220"/>
        <p style="font-size:12px;color:#6B7E8C;">
          Après le scan, votre ancien mot de passe ne sera plus valide.
        </p>
      </div>
      <p style="margin-top:24px;font-size:12px;color:#6B7E8C;">
        Cet email est confidentiel. Ne le transmettez à personne.<br/>
        Équipe COFRAP
      </p>
    </body></html>
    """


def handle(event, context):
    try:
        payload = json.loads(event.body)
        username = payload.get("username", "").strip()

        if not username:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "username is required"}),
                "headers": {"Content-Type": "application/json"},
            }

        email = get_user_email(username)
        if email is None:
            return {
                "statusCode": 404,
                "body": json.dumps({
                    "error": f"Utilisateur '{username}' introuvable. Créez d'abord un compte via create-account."
                }),
                "headers": {"Content-Type": "application/json"},
            }

        plain_password = generate_password(24)
        fernet_key = read_secret("fernet-key").encode()
        encrypted = encrypt(plain_password, fernet_key)
        store_password(username, encrypted)
        qr_b64 = to_qr_base64(plain_password)

        send_email(
            to_addr=email,
            subject=f"[COFRAP] Votre nouveau mot de passe — {username}",
            body_html=_email_body(username),
            images=[
                {"cid": "qr_password", "data_b64": qr_b64},
            ],
        )

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": (
                    f"Nouveau mot de passe généré pour '{username}'. "
                    "Le QR code a été envoyé à l'adresse email enregistrée."
                )
            }),
            "headers": {"Content-Type": "application/json"},
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
            "headers": {"Content-Type": "application/json"},
        }
