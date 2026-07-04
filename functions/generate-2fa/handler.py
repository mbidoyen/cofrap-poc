"""
generate-2fa : génère (ou régénère) un secret TOTP pour un utilisateur existant,
le chiffre avec Fernet, le stocke en base, puis envoie le QR code par email.
Le QR code n'est JAMAIS renvoyé dans le corps de la réponse HTTP.
"""

import json
import time

import pyotp

from _shared import read_secret, encrypt, to_qr_base64, db_connect, send_email


def get_user_email(username: str):
    """
    Retourne l'adresse email de l'utilisateur, ou None si l'utilisateur n'existe pas.
    """
    conn = db_connect()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        conn.close()


def store_mfa(username: str, encrypted_mfa: str) -> None:
    conn = db_connect()
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


def _email_body(username: str) -> str:
    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#1E2761;">
      <h2>Nouveau QR code 2FA — {username}</h2>
      <p>Un nouveau secret TOTP a été généré pour votre compte COFRAP.<br/>
      Scannez le QR code ci-dessous avec <strong>Google Authenticator</strong>,
      <strong>Microsoft Authenticator</strong> ou <strong>Authy</strong>.</p>
      <div style="text-align:center;padding:24px;">
        <img src="cid:qr_totp" alt="QR 2FA" width="220" height="220"/>
        <p style="font-size:12px;color:#6B7E8C;">
          Après le scan, votre ancien code 2FA ne sera plus valide.
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

        # Récupération de l'email depuis la base (vérifie aussi que l'utilisateur existe)
        email = get_user_email(username)
        if email is None:
            return {
                "statusCode": 404,
                "body": json.dumps({
                    "error": f"Utilisateur '{username}' introuvable. Créez d'abord un compte via create-account."
                }),
                "headers": {"Content-Type": "application/json"},
            }

        # --- Génération du nouveau secret TOTP ---
        totp_secret = pyotp.random_base32()
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="COFRAP")
        qr_b64 = to_qr_base64(uri)

        fernet_key = read_secret("fernet-key").encode()
        encrypted = encrypt(totp_secret, fernet_key)
        store_mfa(username, encrypted)

        # --- Envoi du QR code par email (jamais dans la réponse HTTP) ---
        send_email(
            to_addr=email,
            subject=f"[COFRAP] Votre nouveau QR code 2FA — {username}",
            body_html=_email_body(username),
            images=[
                {"cid": "qr_totp", "data_b64": qr_b64},
            ],
        )

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": (
                    f"Secret 2FA régénéré pour '{username}'. "
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
