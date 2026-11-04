import hashlib
import secrets

# Simulate the original file received after decryption.
file_data = b"This is a test file for SEND integrity verification."

# Calculate the correct SHA-256 digest.
correct_hash = hashlib.sha256(file_data).hexdigest()

# Simulate a corrupted or incorrect digest inside the package.
incorrect_hash = "0" * 64

# Same verification logic used in client.py.
actual_hash = hashlib.sha256(file_data).hexdigest()

print("Actual SHA-256:   ", actual_hash)
print("Expected SHA-256: ", incorrect_hash)

if not secrets.compare_digest(actual_hash, incorrect_hash):
    print("\nSHA-256 integrity verification FAILED.")
    print("The receiver correctly rejected the file.")
else:
    print("\nSHA-256 integrity verification PASSED.")
