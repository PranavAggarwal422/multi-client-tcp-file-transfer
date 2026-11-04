from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from key_manager import (
    load_signing_private_key,
    load_signing_public_key
)


def sign_data(data: bytes, username: str) -> bytes:
    """Sign data using the sender's private signing key."""

    private_key = load_signing_private_key(username)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(
    data: bytes,
    signature: bytes,
    sender: str
) -> bool:
    """Verify data using the sender's public signing key."""

    public_key = load_signing_public_key(sender)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    except Exception:
        return False