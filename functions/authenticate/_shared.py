import base64
import io
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
