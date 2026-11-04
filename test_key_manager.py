from key_manager import load_private_key, load_public_key, get_fingerprint

USERNAMES = [
    "Alice", "Bob", "Charlie", "David", "Eve",
    "Frank", "Grace", "Heidi", "Ivan", "Judy"
]

for username in USERNAMES:
    private_key = load_private_key(username)
    public_key = load_public_key(username)

    derived_public_key = private_key.public_key()

    # Verify that the public key matches the private key.
    assert (
        derived_public_key.public_numbers()
        == public_key.public_numbers()
    ), f"Key mismatch for {username}"

    print(f"{username}: PASS")
    print(f"  Fingerprint: {get_fingerprint(public_key)}")

print("\nAll 10 key pairs verified successfully.")
