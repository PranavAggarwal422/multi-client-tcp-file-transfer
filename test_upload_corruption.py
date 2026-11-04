import hashlib
import os
import socket
import ssl

from protocol import make_message, parse_message

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
CERT_FILE = os.path.join("certs", "server-cert.pem")
TEST_FILE = os.path.join("test", "files", "test_100KB.bin")
BUFFER_SIZE = 4096


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def receive_line(sock, initial=b""):
    buffer = bytearray(initial)
    while b"\n" not in buffer:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Connection closed before response.")
        buffer.extend(chunk)

    index = buffer.index(b"\n")
    return bytes(buffer[:index]).decode(), bytes(buffer[index + 1:])


with open(TEST_FILE, "rb") as file:
    original_data = file.read()

if not original_data:
    raise ValueError("Test file is empty.")

original_hash = sha256(original_data)
corrupted_data = bytearray(original_data)
corrupted_data[0] ^= 1
corrupted_data = bytes(corrupted_data)

assert sha256(corrupted_data) != original_hash
print("Original file size:", len(original_data))
print("Original SHA-256:", original_hash)
print("Corrupted data prepared.")

context = ssl.create_default_context(
    ssl.Purpose.SERVER_AUTH,
    cafile=CERT_FILE,
)
context.minimum_version = ssl.TLSVersion.TLSv1_2

with socket.create_connection((SERVER_IP, SERVER_PORT)) as raw_socket:
    with context.wrap_socket(raw_socket, server_hostname=SERVER_IP) as sock:
        sock.sendall(
            make_message("LOGIN", "Alice", "password123").encode()
        )
        login_response, leftover = receive_line(sock)
        print("Login response:", login_response)

        command, fields = parse_message(login_response)
        if command != "OK" or not fields or fields[0] != "LOGIN_SUCCESS":
            raise RuntimeError("Login failed; aborting test.")

        request = make_message(
            "UPLOAD",
            "corruption_test.pdf",
            str(len(corrupted_data)),
            original_hash,
        )
        sock.sendall(request.encode())

        ready_response, leftover = receive_line(sock, leftover)
        print("Upload-ready response:", ready_response)

        command, fields = parse_message(ready_response)
        if command != "OK" or not fields or fields[0] != "READY_FOR_UPLOAD":
            raise RuntimeError("Server did not accept the test upload.")

        for offset in range(0, len(corrupted_data), BUFFER_SIZE):
            sock.sendall(corrupted_data[offset:offset + BUFFER_SIZE])

        result, _ = receive_line(sock)
        print("Integrity result:", result)

        command, fields = parse_message(result)
        if (
            command == "ERROR"
            and fields
            and fields[0] == "INTEGRITY_CHECK_FAILED"
        ):
            print("PASS: Server rejected the corrupted upload.")
        else:
            raise AssertionError("Unexpected integrity result: " + result)

print("Corruption test completed.")
