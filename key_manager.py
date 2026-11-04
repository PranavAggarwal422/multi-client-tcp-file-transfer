
import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

PRIVATE_DIR = os.path.join(PROJECT_DIR, "client_keys")
PUBLIC_DIR = os.path.join(PROJECT_DIR, "trusted_public_keys")


def generate_key_pair(username):
    """Generate an RSA encryption key pair."""

    os.makedirs(PRIVATE_DIR, exist_ok=True)
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    private_path = os.path.join(PRIVATE_DIR, f"{username}_private.pem")
    public_path = os.path.join(PUBLIC_DIR, f"{username}_public.pem")

    if os.path.exists(private_path) or os.path.exists(public_path):
        raise FileExistsError(f"Encryption keys already exist for {username}")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    save_key_pair(private_key, private_path, public_path)


def generate_signing_key_pair(username):
    """Generate a separate RSA key pair for digital signatures."""

    os.makedirs(PRIVATE_DIR, exist_ok=True)
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    private_path = os.path.join(PRIVATE_DIR, f"{username}_sign_private.pem")
    public_path = os.path.join(PUBLIC_DIR, f"{username}_sign_public.pem")

    if os.path.exists(private_path) or os.path.exists(public_path):
        raise FileExistsError(f"Signing keys already exist for {username}")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    save_key_pair(private_key, private_path, public_path)


def save_key_pair(private_key, private_path, public_path):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_path, "xb") as file:
        file.write(private_bytes)

    with open(public_path, "xb") as file:
        file.write(public_bytes)


def load_private_key(username):
    path = os.path.join(PRIVATE_DIR, f"{username}_private.pem")

    with open(path, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


def load_public_key(username):
    path = os.path.join(PUBLIC_DIR, f"{username}_public.pem")

    with open(path, "rb") as file:
        return serialization.load_pem_public_key(file.read())


def load_signing_private_key(username):
    path = os.path.join(PRIVATE_DIR, f"{username}_sign_private.pem")

    with open(path, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


def load_signing_public_key(username):
    path = os.path.join(PUBLIC_DIR, f"{username}_sign_public.pem")

    with open(path, "rb") as file:
        return serialization.load_pem_public_key(file.read())


def get_fingerprint(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return hashlib.sha256(public_bytes).hexdigest()


if __name__ == "__main__":
    usernames = [
    "Alice", "Bob", "Charlie", "David", "Eve",
    "Frank", "Grace", "Heidi", "Ivan", "Judy"
    ]  

    for username in usernames:
        try:
            generate_key_pair(username)
            print(f"Generated encryption keys for {username}")

            generate_signing_key_pair(username)
            print(f"Generated signing keys for {username}")

        except FileExistsError as error:
            print(error)
