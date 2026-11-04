
from key_manager import load_private_key, load_public_key
from e2ee import encrypt_payload, decrypt_payload


def test_normal_encryption():
    alice_message = b"Hello Bob! This is a private message."

    bob_public_key = load_public_key("Bob")
    bob_private_key = load_private_key("Bob")

    context = "MSG|Alice|Bob"

    envelope = encrypt_payload(
        alice_message,
        bob_public_key,
        context
    )

    decrypted = decrypt_payload(
        envelope,
        bob_private_key,
        context
    )

    assert decrypted == alice_message

    print("PASS: Bob successfully decrypted Alice's message.")


def test_wrong_recipient():
    message = b"This message is only for Bob."

    bob_public_key = load_public_key("Bob")
    alice_private_key = load_private_key("Alice")

    envelope = encrypt_payload(
        message,
        bob_public_key,
        "MSG|Alice|Bob"
    )

    try:
        decrypt_payload(
            envelope,
            alice_private_key,
            "MSG|Alice|Bob"
        )
        raise AssertionError("Wrong recipient decrypted the message.")

    except ValueError:
        print("PASS: Alice cannot decrypt a message intended for Bob.")


def test_modified_ciphertext():
    message = b"Original message."

    bob_public_key = load_public_key("Bob")
    bob_private_key = load_private_key("Bob")

    context = "MSG|Alice|Bob"

    envelope = encrypt_payload(
        message,
        bob_public_key,
        context
    )

    # Modify one byte of the encrypted payload.
    import base64

    ciphertext = bytearray(
        base64.b64decode(envelope["ciphertext"])
    )

    ciphertext[0] ^= 1

    envelope["ciphertext"] = base64.b64encode(
        ciphertext
    ).decode("ascii")

    try:
        decrypt_payload(
            envelope,
            bob_private_key,
            context
        )
        raise AssertionError("Modified ciphertext was accepted.")

    except Exception as error:
        if isinstance(error, AssertionError):
            raise

        print("PASS: Modified ciphertext was rejected.")


def test_wrong_context():
    message = b"Context verification test."

    bob_public_key = load_public_key("Bob")
    bob_private_key = load_private_key("Bob")

    envelope = encrypt_payload(
        message,
        bob_public_key,
        "MSG|Alice|Bob"
    )

    try:
        decrypt_payload(
            envelope,
            bob_private_key,
            "MSG|Alice|Charlie"
        )
        raise AssertionError("Incorrect context was accepted.")

    except Exception as error:
        if isinstance(error, AssertionError):
            raise

        print("PASS: Incorrect context was rejected.")


if __name__ == "__main__":
    test_normal_encryption()
    test_wrong_recipient()
    test_modified_ciphertext()
    test_wrong_context()

    print("\nAll E2EE helper tests passed.")
