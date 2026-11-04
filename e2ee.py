
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


AES_KEY_SIZE = 32       # AES-256
NONCE_SIZE = 12         # Recommended GCM nonce size
ENVELOPE_VERSION = 1


def encrypt_payload(plaintext, recipient_public_key, context):
    """
    Encrypt bytes for a recipient.

    A fresh AES-256 key encrypts the payload using AES-GCM.
    RSA-OAEP encrypts the AES key for the recipient.

    context binds the ciphertext to its intended operation,
    sender and recipient.
    """

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    if not isinstance(context, str):
        raise TypeError("context must be a string")

    # Generate a fresh AES-256 key and GCM nonce.
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_SIZE)

    # Encrypt the payload and authenticate its context.
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        context.encode("utf-8")
    )

    # Encrypt the AES key using the recipient's public key.
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "version": ENVELOPE_VERSION,
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii")
    }


def decrypt_payload(envelope, recipient_private_key, context):
    """
    Decrypt an envelope using the recipient's private key.

    Raises an exception if the key is incorrect, the context
    does not match, or the ciphertext has been modified.
    """

    if envelope.get("version") != ENVELOPE_VERSION:
        raise ValueError("Unsupported encrypted-envelope version")

    if not isinstance(context, str):
        raise TypeError("context must be a string")

    encrypted_key = base64.b64decode(
        envelope["encrypted_key"],
        validate=True
    )

    nonce = base64.b64decode(
        envelope["nonce"],
        validate=True
    )

    ciphertext = base64.b64decode(
        envelope["ciphertext"],
        validate=True
    )

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid AES-GCM nonce length")

    # Recover the AES key using the recipient's private key.
    aes_key = recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    if len(aes_key) != AES_KEY_SIZE:
        raise ValueError("Invalid AES key length")

    # Verify authentication tag and context while decrypting.
    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        context.encode("utf-8")
    )
