import hashlib
import tempfile
from pathlib import Path
import secrets

def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "integrity_test.bin"

    path.write_bytes(b"Original file content for integrity testing.")

    original_hash = sha256(path)
    print("Original SHA-256:", original_hash)

    data = bytearray(path.read_bytes())
    data[0] ^= 1
    path.write_bytes(data)

    modified_hash = sha256(path)
    print("Modified SHA-256:", modified_hash)

    integrity_passed = secrets.compare_digest(
        original_hash, modified_hash
    )

    print("Integrity check:", "PASSED" if integrity_passed else "FAILED")
    print("Corruption detected:", not integrity_passed)

    assert not integrity_passed, "Test failed: modification was not detected"

print("Test completed successfully.")
