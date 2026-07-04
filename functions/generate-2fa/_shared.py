import base64
import io
import smtplib
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import psycopg2
import qrcode
from cryptography.fernet import Fernet


def read_secret(name: str) -> str:
    with open(f"/var/openfaas/secrets/{name}", "r") as f:
        return f.read().strip()


def encrypt(plain: str, key: bytes) -> str:
    return Fernet(key).encrypt(plain.encode()).decode()


def decrypt(token: str, key: bytes) -> str:
    return Fernet(key).decrypt(token.encode()).decode()


def to_qr_base64(data: str) -> str:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def db_connect():
    return psycopg2.connect(
        host=read_secret("db-host"),
        dbname=read_secret("db-name"),
        user=read_secret("db-user"),
        password=read_secret("db-password"),
    )


def send_email(to_addr: str, subject: str, body_html: str, images: list = None) -> None:
    """
    Envoie un email HTML avec des images inline (QR codes en base64 PNG).
    images : liste de dicts {"cid": str, "data_b64": str (base64 PNG)}
    Les secrets SMTP sont lus depuis /var/openfaas/secrets/.
    """
    smtp_host = read_secret("smtp-host")
    smtp_port = int(read_secret("smtp-port"))
    smtp_user = read_secret("smtp-user")
    smtp_password = read_secret("smtp-password")
    smtp_from = read_secret("smtp-from")

    msg = MIMEMultipart("related")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = to_addr

    msg_alt = MIMEMultipart("alternative")
    msg.attach(msg_alt)
    msg_alt.attach(MIMEText(body_html, "html", "utf-8"))

    if images:
        for img in images:
            raw = base64.b64decode(img["data_b64"])
            mime_img = MIMEImage(raw, _subtype="png")
            mime_img.add_header("Content-ID", f"<{img['cid']}>")
            mime_img.add_header("Content-Disposition", "inline", filename=f"{img['cid']}.png")
            msg.attach(mime_img)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        # STARTTLS + login uniquement si un mot de passe est configuré
        # (désactivé avec MailHog qui n'exige ni TLS ni authentification)
        if smtp_password:
            server.starttls()
            server.login(smtp_user, smtp_password)
        server.sendmail(smtp_from, [to_addr], msg.as_string())
