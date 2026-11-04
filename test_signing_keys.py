
from key_manager import (
    load_signing_private_key,
    load_signing_public_key,
    get_fingerprint
)

USERNAMES = [
    "Alice", "Bob", "Charlie", "David", "Eve",
    "Frank", "Grace", "Heidi", "Ivan", "Judy"
]
for username in USERNAMES:
    private_key = load_signing_private_key(username)
    public_key = load_signing_public_key(username)

    assert (
        private_key.public_key().public_numbers()
        == public_key.public_numbers()
    ), f"Signing key mismatch for {username}"

    print(f"{username}: PASS")
    print(f"  Signing fingerprint: {get_fingerprint(public_key)}")

print("\nAll signing key pairs verified.")
