from signature_utils import sign_data, verify_signature


# Test 1: Valid signature
message = b"Hello Bob, this is Alice."

signature = sign_data(message, "Alice")

assert verify_signature(message, signature, "Alice")
print("PASS: Valid Alice signature verified.")


# Test 2: Modified message
modified_message = b"Hello Bob, this is Eve."

assert not verify_signature(modified_message, signature, "Alice")
print("PASS: Modified message rejected.")


# Test 3: Wrong sender
assert not verify_signature(message, signature, "Bob")
print("PASS: Signature cannot be verified as Bob.")


print("\nAll digital signature tests passed.")