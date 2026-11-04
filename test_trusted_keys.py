from trusted_keys import verify_trusted_key, TRUSTED_FINGERPRINTS

for username in TRUSTED_FINGERPRINTS:
    assert verify_trusted_key(username, "encryption")
    assert verify_trusted_key(username, "signing")

    print(f"{username}: encryption key TRUSTED")
    print(f"{username}: signing key TRUSTED")

print("\nAll trusted public-key fingerprints verified.")