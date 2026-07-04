"""
create-account : crée un compte utilisateur, génère mot de passe + secret TOTP,
chiffre les deux avec Fernet, les stocke en base, puis envoie les QR codes
par email. Les QR codes ne sont JAMAIS renvoyés dans le corps de la réponse HTTP.
"""

import json
import secrets
import string
import time

import pyotp

from _shared import read_secret, encrypt, to_qr_base64, db_connect, send_email


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


def _email_body(username: str) -> str:
    return f"""
    <html><body style="font-family:Arial,sans-serif;color:#1E2761;">
      <h2>Bienvenue sur COFRAP, {username} !</h2>
      <p>Votre compte a été créé avec succès. Veuillez scanner les deux QR codes
      ci-dessous pour configurer votre accès.</p>
      <table>
        <tr>
          <td style="padding:16px;text-align:center;">
            <p><strong>QR Code mot de passe</strong></p>
            <img src="cid:qr_password" alt="QR mot de passe" width="200" height="200"/>
            <p style="font-size:12px;color:#6B7E8C;">
              Scannez ce code pour récupérer votre mot de passe initial.
            </p>
          </td>
          <td style="padding:16px;text-align:center;">
            <p><strong>QR Code 2FA (TOTP)</strong></p>
            <img src="cid:qr_totp" alt="QR 2FA" width="200" height="200"/>
            <p style="font-size:12px;color:#6B7E8C;">
              Scannez ce code dans Google Authenticator, Microsoft Authenticator
              ou Authy pour activer la double authentification.
            </p>
          </td>
        </tr>
      </table>
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
        email = payload.get("email", "").strip()

        if not username:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "username is required"}),
                "headers": {"Content-Type": "application/json"},
            }
        if not email or "@" not in email:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "a valid email is required"}),
                "headers": {"Content-Type": "application/json"},
            }

        fernet_key = read_secret("fernet-key").encode()

        # --- Génération mot de passe ---
        plain_password = generate_password(24)
        encrypted_password = encrypt(plain_password, fernet_key)
        qr_password_b64 = to_qr_base64(plain_password)

        # --- Génération secret TOTP ---
        totp_secret = pyotp.random_base32()
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="COFRAP")
        encrypted_mfa = encrypt(totp_secret, fernet_key)
        qr_totp_b64 = to_qr_base64(uri)

        # --- Persistance en base (avec email) ---
        conn = db_connect()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO users (username, email, password, mfa, gendate, expired)
                        VALUES (%s, %s, %s, %s, %s, 0)
                        ON CONFLICT (username) DO UPDATE
                        SET email    = EXCLUDED.email,
                            password = EXCLUDED.password,
                            mfa      = EXCLUDED.mfa,
                            gendate  = EXCLUDED.gendate,
                            expired  = 0
                        """,
                        (username, email, encrypted_password, encrypted_mfa, int(time.time())),
                    )
        finally:
            conn.close()

        # --- Envoi des QR codes par email (jamais dans la réponse HTTP) ---
        send_email(
            to_addr=email,
            subject=f"[COFRAP] Vos identifiants de connexion — {username}",
            body_html=_email_body(username),
            images=[
                {"cid": "qr_password", "data_b64": qr_password_b64},
                {"cid": "qr_totp",     "data_b64": qr_totp_b64},
            ],
        )

        return {
            "statusCode": 201,
            "body": json.dumps({
                "message": (
                    f"Compte '{username}' créé avec succès. "
                    "Les QR codes ont été envoyés à l'adresse email enregistrée."
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
