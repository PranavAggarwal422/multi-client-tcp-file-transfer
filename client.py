import ssl
import hashlib
from socket import *
import os, threading
from protocol import parse_message, make_message
import secrets
import base64
import json

from e2ee import encrypt_payload, decrypt_payload
from signature_utils import sign_data, verify_signature
from trusted_keys import verify_trusted_key, TRUSTED_FINGERPRINTS
from key_manager import load_private_key, load_public_key

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
BUFFER_SIZE = 4096
DOWNLOAD_DIR = "downloads"

CERT_FILE = os.path.join("certs", "server-cert.pem")


connection_closed = threading.Event()

upload_event = threading.Event()
upload_result = None
upload_waiting = False

download_event = threading.Event()
download_result = None
download_filename = None
download_filesize = 0

logged_in_username = None
pending_login_username = None

def calculate_file_sha256(file_path):
    """Calculate a file's SHA-256 digest without loading it all into memory."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(BUFFER_SIZE)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()

def send_file(client_socket, filename):
    global upload_result
    global upload_waiting

    if not os.path.isfile(filename):
        print(f"\nFile not found: {filename}")
        return

    filesize = os.path.getsize(filename)
    file_hash = calculate_file_sha256(filename)

    header = make_message(
        "UPLOAD",
        os.path.basename(filename),
        str(filesize),
        file_hash
    )

    # Prepare to wait for the server's response.
    upload_event.clear()
    upload_result = None
    upload_waiting = True

    # Send only the upload request.
    client_socket.sendall(header.encode())

    print(
        f"\nUpload request sent for {filename} "
        f"({filesize} bytes)."
    )

    # Wait for server response.
    if not upload_event.wait(10):
        upload_waiting = False

        print("\nUpload request timed out.")
        print("Closing connection.")

        client_socket.close()
        connection_closed.set()
        return


    upload_waiting = False
    # Check what the server said.
    if upload_result != "READY":
        print("\nUpload was rejected by the server.")
        return

    # Server accepted the upload.
    with open(filename, "rb") as file:
        while True:
            chunk = file.read(BUFFER_SIZE)
            if not chunk:
                break

            client_socket.sendall(chunk)

    print("\nFile data sent.")

def send_file_to_user(client_socket, recipient, filename):
    global upload_result
    global upload_waiting
    global logged_in_username

    if logged_in_username is None:
        print("\nPlease log in first.")
        return

    if not os.path.isfile(filename):
        print(f"\nFile not found: {filename}")
        return

    sender = logged_in_username
    context = f"SEND:{sender}:{recipient}"

    try:
        # Verify recipient's encryption key and sender's signing key.
        verify_trusted_key(recipient, "encryption")
        verify_trusted_key(sender, "signing")

        # Read original file.
        with open(filename, "rb") as file:
            file_data = file.read()

        original_hash = hashlib.sha256(file_data).hexdigest()

        # Package filename, digest and file contents.
        package = {
            "filename": os.path.basename(filename),
            "sha256": original_hash,
            "file_data": base64.b64encode(file_data).decode("ascii")
        }

        package_bytes = json.dumps(
            package,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        # Encrypt the complete package for the recipient.
        recipient_public_key = load_public_key(recipient)

        envelope = encrypt_payload(
            package_bytes,
            recipient_public_key,
            context
        )

        envelope_json = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":")
        )

        encoded_envelope = base64.b64encode(
            envelope_json.encode("utf-8")
        )

        encoded_envelope_text = encoded_envelope.decode("ascii")

        # Sign the encrypted package.
        signed_data = (
            f"{sender}|{recipient}|{context}|{encoded_envelope_text}"
        ).encode("utf-8")

        signature = sign_data(signed_data, sender)

        encoded_signature = base64.b64encode(
            signature
        ).decode("ascii")

        encrypted_size = len(encoded_envelope)

        header = make_message(
            "SEND",
            recipient,
            str(encrypted_size),
            encoded_signature
        )

        # Wait for the server to accept the transfer.
        upload_event.clear()
        upload_result = None
        upload_waiting = True

        client_socket.sendall(header.encode("utf-8"))

        print(
            f"\nEncrypted send request sent to {recipient} "
            f"({encrypted_size} ciphertext bytes)."
        )

        if not upload_event.wait(10):
            upload_waiting = False
            print("\nSend request timed out.")
            return

        upload_waiting = False

        if upload_result != "READY":
            print("\nServer did not accept the encrypted file.")
            return

        # Send encrypted data only.
        client_socket.sendall(encoded_envelope)

        print("\nEncrypted file data sent to server.")

    except Exception as error:
        upload_waiting = False
        print(f"\nCould not send encrypted file: {error}")

def send_private_message(client_socket, recipient, plaintext):
    if logged_in_username is None:
        print("\nPlease log in first.")
        return

    sender = logged_in_username
    context = f"MSG:{sender}:{recipient}"

    try:
        # Verify the recipient's encryption key before using it.
        verify_trusted_key(recipient, "encryption")

        # Verify our own signing key against the pinned fingerprint.
        verify_trusted_key(sender, "signing")

        recipient_public_key = load_public_key(recipient)

        # Encrypt the message for the recipient.
        envelope = encrypt_payload(
            plaintext.encode("utf-8"),
            recipient_public_key,
            context
        )

        # Serialize the envelope deterministically.
        envelope_json = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":")
        )

        encoded_envelope = base64.b64encode(
            envelope_json.encode("utf-8")
        ).decode("ascii")

        # Bind the sender, recipient, operation and envelope to the signature.
        signed_data = (
            f"{sender}|{recipient}|{context}|{encoded_envelope}"
        ).encode("utf-8")

        signature = sign_data(signed_data, sender)

        encoded_signature = base64.b64encode(
            signature
        ).decode("ascii")

        request = make_message(
            "MSG",
            recipient,
            encoded_envelope,
            encoded_signature
        )

        client_socket.sendall(request.encode("utf-8"))
        print(f"\nEncrypted private message sent to {recipient}.")

    except Exception as error:
        print(f"\nCould not send private message: {error}")

def send_broadcast_message(client_socket, plaintext):
    global logged_in_username

    if logged_in_username is None:
        print("\nPlease log in first.")
        return

    sender = logged_in_username

    try:
        verify_trusted_key(sender, "signing")

        broadcast_data = {}

        for recipient in TRUSTED_FINGERPRINTS:
            if recipient == sender:
                continue

            # Verify the recipient's encryption key.
            verify_trusted_key(recipient, "encryption")

            recipient_public_key = load_public_key(recipient)
            context = f"BROADCAST:{sender}:{recipient}"

            # Encrypt separately for this recipient.
            envelope = encrypt_payload(
                plaintext.encode("utf-8"),
                recipient_public_key,
                context
            )

            envelope_json = json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":")
            )

            encoded_envelope = base64.b64encode(
                envelope_json.encode("utf-8")
            ).decode("ascii")

            # Sign the recipient-specific encrypted envelope.
            signed_data = (
                f"{sender}|{recipient}|{context}|{encoded_envelope}"
            ).encode("utf-8")

            signature = sign_data(signed_data, sender)

            encoded_signature = base64.b64encode(
                signature
            ).decode("ascii")

            broadcast_data[recipient] = {
                "envelope": encoded_envelope,
                "signature": encoded_signature
            }

        payload_json = json.dumps(
            broadcast_data,
            sort_keys=True,
            separators=(",", ":")
        )

        encoded_payload = base64.b64encode(
            payload_json.encode("utf-8")
        ).decode("ascii")

        request = make_message("BROADCAST", encoded_payload)
        client_socket.sendall(request.encode("utf-8"))

        print("\nEncrypted broadcast sent to the server.")

    except Exception as error:
        print(f"\nCould not send broadcast: {error}")

def handle_server_message(message):
    global upload_result
    global logged_in_username
    global pending_login_username
    command, fields = parse_message(message)
    

    if command == "OK":
        if len(fields) == 0:
            print("\nServer: OK")
            return

        operation = fields[0]

        if operation == "LOGIN_SUCCESS":
            logged_in_username = pending_login_username
            pending_login_username = None

            print("\nLogin successful.")

        elif operation == "MSG_SENT":
            print("\nMessage sent successfully.")

        elif operation == "BROADCAST_SENT":
            print("\nBroadcast sent successfully.")

        elif operation == "USERS":
            if len(fields) >= 2 and fields[1]:
                user_list = fields[1]
                print(f"\nOnline users: {user_list}")
            else:
                print("\nNo users are currently online.")

        elif operation == "READY_FOR_UPLOAD":
            print("\nServer is ready to receive the file.")
            if upload_waiting:
                upload_result = "READY"
                upload_event.set()

        elif operation == "READY_FOR_SEND":
            print("\nServer is ready to receive the file for sending.")
            if upload_waiting:
                upload_result = "READY"
                upload_event.set()

        elif operation == "LOGOUT_SUCCESS":
            print("\nLogout successful.")
            connection_closed.set()

        else:
            print(f"\nSuccess: {operation}")

    elif command == "ERROR":
        if len(fields) == 0:
            print("\nError: Unknown error")
            return

        if fields and fields[0] in (
            "INVALID_CREDENTIALS",
            "ALREADY_LOGGED_IN",
            "INVALID_LOGIN_FORMAT"
        ):
            pending_login_username = None
            logged_in_username = None

        error_type = fields[0]

        if upload_waiting:
            upload_result = "ERROR"
            upload_event.set()

        if error_type == "BROADCAST_PARTIAL":
            if len(fields) >= 2:
                print(
                    f"\nBroadcast partially sent. "
                    f"Could not reach: {fields[1]}"
                )
            else:
                print("\nBroadcast was only partially sent.")

        else:
            print(f"\nError: {error_type}")

    elif command == "MSG":
        if len(fields) != 3:
            print("\nInvalid encrypted MSG received from server.")
            return

        sender = fields[0]
        encoded_envelope = fields[1]
        encoded_signature = fields[2]

        try:
            if logged_in_username is None:
                raise ValueError("You are not logged in.")

            recipient = logged_in_username
            context = f"MSG:{sender}:{recipient}"

            # Verify the sender's signing key is trusted.
            verify_trusted_key(sender, "signing")

            # Verify our own encryption key is trusted.
            verify_trusted_key(recipient, "encryption")

            # Reconstruct the exact data that the sender signed.
            signed_data = (
                f"{sender}|{recipient}|{context}|{encoded_envelope}"
            ).encode("utf-8")

            signature = base64.b64decode(
                encoded_signature,
                validate=True
            )

            if not verify_signature(signed_data, signature, sender):
                raise ValueError("Digital signature verification failed.")

            # Decode the encrypted envelope.
            envelope_json = base64.b64decode(
                encoded_envelope,
                validate=True
            ).decode("utf-8")

            envelope = json.loads(envelope_json)

            # Decrypt using the recipient's private encryption key.
            private_key = load_private_key(recipient)

            plaintext = decrypt_payload(
                envelope,
                private_key,
                context
            )

            message_text = plaintext.decode("utf-8")

            print(f"\n{sender}: {message_text}")

        except Exception as error:
            print(f"\nPrivate message rejected: {error}")

    elif command == "BROADCAST":
        if len(fields) != 3:
            print("\nInvalid encrypted BROADCAST received.")
            return

        sender = fields[0]
        encoded_envelope = fields[1]
        encoded_signature = fields[2]

        try:
            if logged_in_username is None:
                raise ValueError("You are not logged in.")

            recipient = logged_in_username
            context = f"BROADCAST:{sender}:{recipient}"

            # Verify the sender's signing key.
            verify_trusted_key(sender, "signing")

            # Verify our encryption key.
            verify_trusted_key(recipient, "encryption")

            signed_data = (
                f"{sender}|{recipient}|{context}|{encoded_envelope}"
            ).encode("utf-8")

            signature = base64.b64decode(
                encoded_signature,
                validate=True
            )

            if not verify_signature(signed_data, signature, sender):
                raise ValueError("Digital signature verification failed.")

            envelope_json = base64.b64decode(
                encoded_envelope,
                validate=True
            ).decode("utf-8")

            envelope = json.loads(envelope_json)

            private_key = load_private_key(recipient)

            plaintext = decrypt_payload(
                envelope,
                private_key,
                context
            )

            message_text = plaintext.decode("utf-8")

            print(f"\n{sender} [Broadcast]: {message_text}")

        except Exception as error:
            print(f"\nBroadcast rejected: {error}")

    else:
        print(f"\nUnknown server message: {message}")

def receive_download_file(client_socket, receive_buffer, filename, filesize, expected_hash):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    file_path = os.path.join(DOWNLOAD_DIR, filename)

    received = 0

    try:
        with open(file_path, "wb") as file:
            # First use any file bytes already present in the receive buffer.
            if receive_buffer:
                bytes_to_write = min(len(receive_buffer), filesize)
                file.write(receive_buffer[:bytes_to_write])

                del receive_buffer[:bytes_to_write]
                received += bytes_to_write

            # Receive remaining file bytes.
            while received < filesize:
                bytes_to_receive = min(BUFFER_SIZE, filesize - received)
                chunk = client_socket.recv(bytes_to_receive)

                if not chunk:
                    raise ConnectionError("Server disconnected during file transfer.")

                file.write(chunk)
                received += len(chunk)

        actual_hash = calculate_file_sha256(file_path)
        if not secrets.compare_digest(actual_hash, expected_hash):
            os.remove(file_path)
            print(f"\nDownload failed: SHA-256 integrity check FAILED for {filename}.")
            return

        print(
            f"\nDownload successful: {filename} "
            f"({filesize} bytes). SHA-256 integrity check: PASSED."
        )

    except Exception as e:
        print(f"\nDownload failed: {e}")

def receive_sent_file(client_socket, receive_buffer, sender, filesize,encoded_signature):
    global logged_in_username

    try:
        # Receive the exact ciphertext length.
        encrypted_data = bytearray()

        if receive_buffer:
            bytes_to_read = min(len(receive_buffer), filesize)
            encrypted_data.extend(receive_buffer[:bytes_to_read])
            del receive_buffer[:bytes_to_read]

        while len(encrypted_data) < filesize:
            remaining = filesize - len(encrypted_data)
            chunk = client_socket.recv(min(BUFFER_SIZE, remaining))

            if not chunk:
                raise ConnectionError(
                    "Connection closed during encrypted file transfer."
                )

            encrypted_data.extend(chunk)

        recipient = logged_in_username

        if recipient is None:
            raise ValueError("Recipient is not logged in.")

        context = f"SEND:{sender}:{recipient}"

        # Convert ciphertext to its encoded envelope representation.
        encoded_envelope = encrypted_data.decode("ascii")

        # Verify trusted keys.
        verify_trusted_key(sender, "signing")
        verify_trusted_key(recipient, "encryption")

        # Verify sender's digital signature before decryption.
        signed_data = (
            f"{sender}|{recipient}|{context}|{encoded_envelope}"
        ).encode("utf-8")

        signature = base64.b64decode(
            encoded_signature,
            validate=True
        )

        if not verify_signature(signed_data, signature, sender):
            raise ValueError("Digital signature verification failed.")

        # Decode the encrypted envelope.
        envelope_json = base64.b64decode(
            encoded_envelope,
            validate=True
        ).decode("utf-8")

        envelope = json.loads(envelope_json)

        # Decrypt using the recipient's private key.
        private_key = load_private_key(recipient)

        package_bytes = decrypt_payload(
            envelope,
            private_key,
            context
        )

        package = json.loads(package_bytes.decode("utf-8"))

        filename = package["filename"]
        expected_hash = package["sha256"]

        # Validate filename to prevent path traversal.
        if not filename or os.path.basename(filename) != filename:
            raise ValueError("Invalid filename in decrypted package.")

        file_data = base64.b64decode(
            package["file_data"],
            validate=True
        )

        # Verify original file integrity.
        actual_hash = hashlib.sha256(file_data).hexdigest()

        if not secrets.compare_digest(actual_hash, expected_hash):
            raise ValueError("SHA-256 integrity verification failed.")

        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        file_path = os.path.join(DOWNLOAD_DIR, filename)

        with open(file_path, "wb") as file:
            file.write(file_data)

        print(
            f"\nEncrypted file successfully received from {sender}: "
            f"{filename} ({len(file_data)} bytes)."
        )

        print("Digital signature verification: PASSED.")
        print("SHA-256 integrity verification: PASSED.")

    except Exception as error:
        print(f"\nEncrypted file rejected: {error}")

def receive_messages(client_socket):
    """
    Continuously receive messages from the server.
    """

    receive_buffer = bytearray()

    try:
        while True:
            # Receive data from server.
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                print("\nServer disconnected.")
                break

            receive_buffer.extend(data)

            # Process all complete control messages currently present in the buffer.
            while b"\n" in receive_buffer:
                newline_index = receive_buffer.index(b"\n")
                message_bytes = bytes(receive_buffer[:newline_index])

                del receive_buffer[:newline_index + 1]
                message = message_bytes.decode()
                command, fields = parse_message(message)

                # Handle DOWNLOAD response specially.
                if (
                    command == "OK"
                    and len(fields) >= 4
                    and fields[0] == "READY_FOR_DOWNLOAD"
                ):
                    filename = fields[1]
                    filesize = int(fields[2])
                    expected_hash = fields[3]

                    print(
                        f"\nStarting download of {filename} "
                        f"({filesize} bytes)..."
                    )

                    receive_download_file(
                        client_socket,
                        receive_buffer,
                        filename,
                        filesize,
                        expected_hash
                    )

                elif (
                    command == "OK"
                    and len(fields) >= 4
                    and fields[0] == "READY_FOR_RECEIVE"
                ):
                    sender = fields[1]
                    filesize = int(fields[2])
                    encoded_signature = fields[3]

                    print(
                        f"\nReceiving encrypted file from {sender} "
                        f"({filesize} ciphertext bytes)..."
                    )

                    receive_sent_file(
                        client_socket,
                        receive_buffer,
                        sender,
                        filesize,
                        encoded_signature
                    )

                else:
                    handle_server_message(message)

    except ConnectionResetError:
        print("\nConnection to server was lost.")

    except Exception as e:
        print(f"\nAn error occurred while receiving messages: {e}")

    finally:
        client_socket.close()
        connection_closed.set()


def start_client():
    global logged_in_username
    global pending_login_username

    # Trust the certificate generated for our server.
    tls_context = ssl.create_default_context(
    ssl.Purpose.SERVER_AUTH,
    cafile=CERT_FILE
    )

    # Require certificate validation and hostname verification.
    tls_context.verify_mode = ssl.CERT_REQUIRED
    tls_context.check_hostname = True
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

    raw_socket = socket(AF_INET, SOCK_STREAM)

    try:
        raw_socket.connect((SERVER_IP, SERVER_PORT))

        # Establish TLS and verify the server's certificate.
        client_socket = tls_context.wrap_socket(
            raw_socket,
            server_hostname=SERVER_IP
        )

    except Exception:
        raw_socket.close()
        raise

    print(
        f"Secure TLS connection established with "
        f"{SERVER_IP}:{SERVER_PORT}"
    )

    # Start the existing thread to continuously receive messages.
    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket,)
    )
    receive_thread.start()

    # Main thread continues to handle keyboard input.
    while True:
        command = input()

        if connection_closed.is_set():
            break

        if command.startswith("UPLOAD|"):
            parts = command.split("|")

            if len(parts) != 2:
                print("\nUsage: UPLOAD|filename")
                continue

            filename = parts[1]
            send_file(client_socket, filename)

        elif command.startswith("SEND|"):
            parts = command.split("|")

            if len(parts) != 3:
                print("\nUsage: SEND|recipient|filename")
                continue

            recipient = parts[1]
            filename = parts[2]
            send_file_to_user(client_socket, recipient, filename)

        elif command.startswith("MSG|"):
            parts = command.split("|", 2)

            if len(parts) != 3:
                print("\nUsage: MSG|recipient|message")
                continue

            recipient = parts[1]
            message_text = parts[2]

            if not recipient or not message_text:
                print("\nRecipient and message cannot be empty.")
                continue

            send_private_message(
                client_socket,
                recipient,
                message_text
            )

        elif command.startswith("BROADCAST|"):
            parts = command.split("|", 1)

            if len(parts) != 2 or not parts[1]:
                print("\nUsage: BROADCAST|message")
                continue

            send_broadcast_message(
                client_socket,
                parts[1]
            )
            
        else:
            if command.startswith("LOGIN|"):
                parts = command.split("|")

                if len(parts) == 3:
                    pending_login_username = parts[1]
                    logged_in_username = parts[1]

            client_socket.sendall((command + "\n").encode())

    client_socket.close()



if __name__ == "__main__":
    start_client()

    