import os
import ssl
import hashlib
import secrets
from socket import *
from protocol import parse_message, make_message
import threading
import json
import time
import base64

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
BACKLOG = 10
BUFFER_SIZE = 4096
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_FILES_DIR = os.path.join(PROJECT_DIR, "server_files")


CERT_FILE = os.path.join("certs", "server-cert.pem")
KEY_FILE = os.path.join("certs", "server-key.pem")

PASSWORD_ITERATIONS = 600_000
PASSWORD_HASH_BYTES = 32

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(PROJECT_DIR, "password_records.json")


def hash_password(password, salt, iterations=PASSWORD_ITERATIONS):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=PASSWORD_HASH_BYTES,
    )


def load_password_records():
    if not os.path.exists(RECORDS_FILE):
        raise FileNotFoundError(
            "password_records.json not found. "
            "Run setup_passwords.py first."
        )

    with open(RECORDS_FILE, "r", encoding="utf-8") as file:
        records = json.load(file)

    users = {}

    for username, record in records.items():
        salt = bytes.fromhex(record["salt"])
        password_hash = bytes.fromhex(record["password_hash"])
        iterations = int(record["iterations"])

        if len(salt) != 16 or len(password_hash) != PASSWORD_HASH_BYTES:
            raise ValueError(f"Invalid password record for {username}")

        if iterations <= 0:
            raise ValueError(f"Invalid iteration count for {username}")

        users[username] = (salt, password_hash, iterations)

    return users


USERS = load_password_records()




active_users = {}
active_users_lock = threading.Lock()

def calculate_file_sha256(file_path):
    """Calculate a file's SHA-256 digest in chunks."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(BUFFER_SIZE)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()

def send_file(connection_socket, file_path, filesize):
    sent = 0

    with open(file_path, "rb") as file:
        while sent < filesize:
            chunk = file.read(min(BUFFER_SIZE, filesize - sent))
            if not chunk:
                raise ConnectionError("File ended before all bytes were sent.")

            connection_socket.sendall(chunk)
            sent += len(chunk)

def send_message(connection_socket, send_lock, message):
    with send_lock:
        connection_socket.sendall(message.encode())

def receive_file(connection_socket, receive_buffer, file, filesize):
    received = 0

    # First use any file bytes already present in receive_buffer
    if receive_buffer:
        bytes_to_write = min(len(receive_buffer), filesize)
        file.write(receive_buffer[:bytes_to_write])
        del receive_buffer[:bytes_to_write]

        received += bytes_to_write

    # Receive the remaining file bytes from the socket
    while received < filesize:
        bytes_to_receive = min(BUFFER_SIZE, filesize - received)
        chunk = connection_socket.recv(bytes_to_receive)

        if not chunk:
            raise ConnectionError("Client disconnected during file transfer.")

        file.write(chunk)
        received += len(chunk)

def receive_message(connection_socket, receive_buffer):
    while b"\n" not in receive_buffer:
        data = connection_socket.recv(BUFFER_SIZE)

        if not data:
            return None

        receive_buffer.extend(data)

    newline_index = receive_buffer.index(b"\n")

    message_bytes = bytes(receive_buffer[:newline_index])

    del receive_buffer[:newline_index + 1]

    return message_bytes.decode()

def receive_and_forward_file(sender_socket, sender_buffer, receiver_socket, filename, filesize):
    sent = 0

    while sent < filesize:
        if sender_buffer:
            bytes_to_send = min(len(sender_buffer), filesize - sent)
            receiver_socket.sendall(sender_buffer[:bytes_to_send])
            del sender_buffer[:bytes_to_send]
            sent += bytes_to_send

        else:
            bytes_to_receive = min(BUFFER_SIZE, filesize - sent)
            chunk = sender_socket.recv(bytes_to_receive)

            if not chunk:
                raise ConnectionError("Sender disconnected during file transfer.")

            receiver_socket.sendall(chunk)
            sent += len(chunk)

def handle_client(connection_socket, client_address):
    """
    Handle communication with one connected client.
    """

    print(f"Connection from: {client_address}")

    username = None
    receive_buffer = bytearray()
    send_lock = threading.Lock()

    try:
        while True:
            message = receive_message(connection_socket, receive_buffer)
            if message is None:
                break

            command, fields = parse_message(message)

            print(f"Received command: {command}")
            # print(f"Fields: {fields}")

            # LOGIN
            if command == "LOGIN":
                    if len(fields) != 2:
                        response = make_message("ERROR", "INVALID_LOGIN_FORMAT")
                        send_message(connection_socket, send_lock, response)
                        continue

                    # A connection can have only one logged-in user
                    if username is not None:
                        response = make_message("ERROR", "ALREADY_AUTHENTICATED")
                        send_message(connection_socket, send_lock, response)
                        continue

                    login_username = fields[0]
                    password = fields[1]

                    # Check whether username exists
                    if login_username not in USERS:
                        response = make_message("ERROR", "INVALID_CREDENTIALS")
                        send_message(connection_socket, send_lock, response)
                        continue

                    # Verify the password against the stored salt and hash.
                    stored_salt, stored_hash, iterations = USERS[login_username]
                    candidate_hash = hash_password(password, stored_salt, iterations)

                    if not secrets.compare_digest(candidate_hash, stored_hash):
                        response = make_message("ERROR", "INVALID_CREDENTIALS")
                        send_message(connection_socket, send_lock, response)
                        continue


                    # Check and add active user
                    with active_users_lock:
                        if login_username in active_users:
                            response = make_message("ERROR", "ALREADY_LOGGED_IN")

                        else:
                            active_users[login_username] = (connection_socket, send_lock)
                            username = login_username
                            response = make_message("OK", "LOGIN_SUCCESS")

                    send_message(connection_socket, send_lock, response)

            # LIST
            elif command == "LIST":
                    if username is None:
                        response = make_message("ERROR", "NOT_AUTHENTICATED")
                        send_message(connection_socket, send_lock, response)
                        continue

                    with active_users_lock:
                        usernames = list(active_users.keys())

                    user_list = ",".join(usernames)

                    response = make_message("OK", "USERS", user_list)
                    send_message(connection_socket, send_lock, response)

            # MSG - End-to-end encrypted private messaging
            elif command == "MSG":
                if username is None:
                    response = make_message("ERROR", "NOT_AUTHENTICATED")
                    send_message(connection_socket, send_lock, response)
                    continue

                # MSG requires recipient, encrypted envelope and signature.
                if len(fields) != 3:
                    response = make_message("ERROR", "INVALID_MSG_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                recipient = fields[0]
                encrypted_envelope = fields[1]
                signature = fields[2]

                if not recipient or not encrypted_envelope or not signature:
                    response = make_message("ERROR", "INVALID_MSG_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                if recipient == username:
                    response = make_message("ERROR", "CANNOT_MESSAGE_SELF")
                    send_message(connection_socket, send_lock, response)
                    continue

                # Find recipient's socket.
                with active_users_lock:
                    recipient_info = active_users.get(recipient)

                if recipient_info is None:
                    response = make_message("ERROR", "USER_NOT_ONLINE")
                    send_message(connection_socket, send_lock, response)
                    continue

                recipient_socket, recipient_send_lock = recipient_info

                # Forward opaque encrypted data. The server does not decrypt it.
                forwarded_message = make_message(
                    "MSG",
                    username,
                    encrypted_envelope,
                    signature
                )
                # tampered_signature = (
                #     ("A" if signature[0] != "A" else "B")
                #     + signature[1:]
                # )

                # forwarded_message = make_message(
                #     "MSG",
                #     username,
                #     encrypted_envelope,
                #     tampered_signature
                # )

                try:
                    send_message(
                        recipient_socket,
                        recipient_send_lock,
                        forwarded_message
                    )

                except Exception as e:
                    print(f"Could not send message to {recipient}. Error: {e}")
                    response = make_message("ERROR", "DELIVERY_FAILED")
                    send_message(connection_socket, send_lock, response)
                    continue

                # Tell sender that the message was delivered.
                response = make_message("OK", "MSG_SENT")
                send_message(connection_socket, send_lock, response)
             
            # LOGOUT
            elif command == "LOGOUT":
                    if username is None:
                        response = make_message("ERROR", "NOT_AUTHENTICATED")
                        send_message(connection_socket, send_lock, response)
                        continue

                    response = make_message("OK", "LOGOUT_SUCCESS")
                    send_message(connection_socket, send_lock, response)

                    with active_users_lock:
                        user_info = active_users.get(username)
                        if user_info is not None:
                            user_socket, user_send_lock = user_info
                            if user_socket == connection_socket:
                                del active_users[username]

                    print(f"User {username} logged out.")
                    username = None
                    break

            # BROADCAST - End-to-end encrypted broadcast
            elif command == "BROADCAST":
                if username is None:
                    response = make_message("ERROR", "NOT_AUTHENTICATED")
                    send_message(connection_socket, send_lock, response)
                    continue

                if len(fields) != 1:
                    response = make_message("ERROR", "INVALID_BROADCAST_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                try:
                    # Decode the recipient-specific encrypted envelopes.
                    broadcast_data = json.loads(
                        __import__("base64").b64decode(
                            fields[0],
                            validate=True
                        ).decode("utf-8")
                    )

                    if not isinstance(broadcast_data, dict) or not broadcast_data:
                        raise ValueError("Invalid broadcast payload")

                except Exception:
                    response = make_message("ERROR", "INVALID_BROADCAST_PAYLOAD")
                    send_message(connection_socket, send_lock, response)
                    continue

                # Get currently online users.
                with active_users_lock:
                    recipients = [
                        (recipient, recipient_socket, recipient_send_lock)
                        for recipient, (recipient_socket, recipient_send_lock)
                        in active_users.items()
                        if recipient != username
                    ]

                failed_recipients = []
                delivered_count = 0

                for recipient, recipient_socket, recipient_send_lock in recipients:
                    recipient_payload = broadcast_data.get(recipient)

                    if not isinstance(recipient_payload, dict):
                        failed_recipients.append(recipient)
                        continue

                    encrypted_envelope = recipient_payload.get("envelope")
                    signature = recipient_payload.get("signature")

                    if not isinstance(encrypted_envelope, str) or not isinstance(signature, str):
                        failed_recipients.append(recipient)
                        continue

                    forwarded_message = make_message(
                        "BROADCAST",
                        username,
                        encrypted_envelope,
                        signature
                    )
                    # tampered_signature = (
                    #     ("A" if signature[0] != "A" else "B")
                    #     + signature[1:]
                    # )

                    # forwarded_message = make_message(
                    #     "BROADCAST",
                    #     username,
                    #     encrypted_envelope,
                    #     tampered_signature
                    # )

                    try:
                        send_message(
                            recipient_socket,
                            recipient_send_lock,
                            forwarded_message
                        )
                        delivered_count += 1

                    except Exception as error:
                        print(
                            f"Could not broadcast to {recipient}. Error: {error}"
                        )
                        failed_recipients.append(recipient)

                if failed_recipients:
                    failed_users = ",".join(failed_recipients)
                    response = make_message(
                        "ERROR",
                        "BROADCAST_PARTIAL",
                        failed_users
                    )
                elif delivered_count == 0:
                    response = make_message("ERROR", "NO_BROADCAST_RECIPIENTS")
                else:
                    response = make_message("OK", "BROADCAST_SENT")

                send_message(connection_socket, send_lock, response)

            # UPLOAD
            elif command == "UPLOAD":
                if username is None:
                    response = make_message("ERROR", "NOT_AUTHENTICATED")
                    send_message(connection_socket, send_lock, response)
                    continue

                if len(fields) != 3:
                    response = make_message("ERROR", "INVALID_UPLOAD_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                filename = fields[0]
                expected_hash = fields[2]

                if not filename or os.path.basename(filename) != filename:
                    response = make_message("ERROR", "INVALID_FILENAME")
                    send_message(connection_socket, send_lock, response)
                    continue

                try:
                    filesize = int(fields[1])
                except ValueError:
                    response = make_message("ERROR", "INVALID_FILESIZE")
                    send_message(connection_socket, send_lock, response)
                    continue

                if filesize < 0:
                    response = make_message("ERROR", "INVALID_FILESIZE")
                    send_message(connection_socket, send_lock, response)
                    continue

                file_path = os.path.join(SERVER_FILES_DIR, filename)
                upload_start = time.perf_counter()


                try:
                    # Tell the client that the upload request was accepted.
                    response = make_message("OK", "READY_FOR_UPLOAD")
                    send_message(connection_socket, send_lock, response)

                    # Receive and save the actual file data.
                    with open(file_path, "wb") as file:
                        receive_file(connection_socket, receive_buffer, file, filesize)

                    # Independently calculate the digest of the received file.
                    actual_hash = calculate_file_sha256(file_path)

                    if not secrets.compare_digest(actual_hash, expected_hash):
                        # Do not retain a file that failed integrity verification.
                        os.remove(file_path)

                        response = make_message("ERROR", "INTEGRITY_CHECK_FAILED")
                        send_message(connection_socket, send_lock, response)

                        print(f"Upload rejected: integrity check failed for {filename}.")
                        continue

                    # The received file matches the sender's original digest.
                    response = make_message("OK", "UPLOAD_SUCCESS")
                    send_message(connection_socket, send_lock, response)

                    upload_elapsed = time.perf_counter() - upload_start
                    throughput_mbps = (
                        filesize / (1024 * 1024) / upload_elapsed
                        if upload_elapsed > 0
                        else 0.0
                    )

                    print(
                        f"User {username} uploaded {filename} ({filesize} bytes). "
                        f"SHA-256 integrity check: PASSED. "
                        f"Elapsed: {upload_elapsed:.6f} s, "
                        f"throughput: {throughput_mbps:.3f} MiB/s."
                    )

                except ConnectionError as error:
                    print(error)
                    break

            # DOWNLOAD
            elif command == "DOWNLOAD":
                if username is None:
                    response = make_message("ERROR", "NOT_AUTHENTICATED")
                    send_message(connection_socket, send_lock, response)
                    continue

                if len(fields) != 1:
                    response = make_message("ERROR", "INVALID_DOWNLOAD_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                filename = fields[0]

                if not filename or os.path.basename(filename) != filename:
                    response = make_message("ERROR", "INVALID_FILENAME")
                    send_message(connection_socket, send_lock, response)
                    continue

                file_path = os.path.join(SERVER_FILES_DIR, filename)

                if not os.path.isfile(file_path):
                    response = make_message("ERROR", "FILE_NOT_FOUND")
                    send_message(connection_socket, send_lock, response)
                    continue

                filesize = os.path.getsize(file_path)
                file_hash = calculate_file_sha256(file_path)

                response = make_message(
                    "OK",
                    "READY_FOR_DOWNLOAD",
                    filename,
                    str(filesize),
                    file_hash
                )
                
                try:
                    download_start = time.perf_counter()

                    with send_lock:
                        connection_socket.sendall(response.encode())
                        send_file(connection_socket, file_path, filesize)

                    download_elapsed = time.perf_counter() - download_start
                    throughput_mbps = (
                        filesize / (1024 * 1024) / download_elapsed
                        if download_elapsed > 0
                        else 0.0
                    )

                    print(
                        f"Sent {filename} ({filesize} bytes) to {username}. "
                        f"Elapsed: {download_elapsed:.6f} s, "
                        f"throughput: {throughput_mbps:.3f} MiB/s."
                    )

                except Exception as e:
                    print(f"Download failed for {username}: {e}")
                    break

            # SEND - End-to-end encrypted client-to-client file transfer
            elif command == "SEND":
                if username is None:
                    response = make_message("ERROR", "NOT_AUTHENTICATED")
                    send_message(connection_socket, send_lock, response)
                    continue

                # Fields: recipient, encrypted filesize, signature
                if len(fields) != 3:
                    response = make_message("ERROR", "INVALID_SEND_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                recipient = fields[0]
                signature = fields[2]

                if not recipient or not signature:
                    response = make_message("ERROR", "INVALID_SEND_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                try:
                    filesize = int(fields[1])
                except ValueError:
                    response = make_message("ERROR", "INVALID_FILESIZE")
                    send_message(connection_socket, send_lock, response)
                    continue

                if filesize <= 0:
                    response = make_message("ERROR", "INVALID_FILESIZE")
                    send_message(connection_socket, send_lock, response)
                    continue

                if recipient == username:
                    response = make_message("ERROR", "CANNOT_SEND_TO_SELF")
                    send_message(connection_socket, send_lock, response)
                    continue

                with active_users_lock:
                    recipient_info = active_users.get(recipient)

                if recipient_info is None:
                    response = make_message("ERROR", "USER_NOT_ONLINE")
                    send_message(connection_socket, send_lock, response)
                    continue

                recipient_socket, recipient_send_lock = recipient_info

                send_start = time.perf_counter()

                try:
                    # Tell sender that the server is ready.
                    response = make_message("OK", "READY_FOR_SEND")
                    send_message(connection_socket, send_lock, response)

                    # Notify receiver about the incoming encrypted file.
                    response = make_message(
                        "OK",
                        "READY_FOR_RECEIVE",
                        username,
                        str(filesize),
                        signature
                    )

                    # TEST ONLY: Tamper with the sender's digital signature.
                    # tampered_signature = (
                    #     ("A" if signature[0] != "A" else "B") + signature[1:]
                    # )

                    # response = make_message(
                    #     "OK",
                    #     "READY_FOR_RECEIVE",
                    #     username,
                    #     str(filesize),
                    #     tampered_signature
                    # )

                    with recipient_send_lock:
                        recipient_socket.sendall(response.encode())

                        # Relay ciphertext without decrypting it.
                        receive_and_forward_file(
                            connection_socket,
                            receive_buffer,
                            recipient_socket,
                            "encrypted_payload",
                            filesize
                        )

                    response = make_message("OK", "SEND_SUCCESS")
                    send_message(connection_socket, send_lock, response)

                    send_elapsed = time.perf_counter() - send_start

                    throughput_mbps = (
                        filesize / (1024 * 1024) / send_elapsed
                        if send_elapsed > 0
                        else 0.0
                    )

                    print(
                        f"User {username} sent an encrypted file "
                        f"({filesize} ciphertext bytes) to {recipient}. "
                        f"Elapsed: {send_elapsed:.6f} s, "
                        f"throughput: {throughput_mbps:.3f} MiB/s."
                    )

                except Exception as error:
                    print(
                        f"Encrypted send failed from {username} "
                        f"to {recipient}: {error}"
                    )

                    try:
                        response = make_message("ERROR", "SEND_FAILED")
                        send_message(connection_socket, send_lock, response)
                    except Exception:
                        pass

                    break

                            
    except(ConnectionResetError, ConnectionAbortedError):
        print(f"Client {client_address} disconnected unexpectedly.")

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")

    finally:
        # Remove user from active_users when connection closes
        if username is not None:
            with active_users_lock:
                user_info = active_users.get(username)

                if user_info is not None:
                    user_socket, user_send_lock = user_info

                    if user_socket == connection_socket:
                        del active_users[username]

            print(f"User {username} logged out.")

        connection_socket.close()
        print(f"Connection closed: {client_address}")


def start_server():
    os.makedirs(SERVER_FILES_DIR, exist_ok=True)

    # Configure TLS for the server.
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(
        certfile=CERT_FILE,
        keyfile=KEY_FILE
    )

    # Create the ordinary TCP listening socket.
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(BACKLOG)

    print(f"TLS server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        connection_socket, client_address = server_socket.accept()

        try:
            # Complete the TLS handshake with this client.
            secure_socket = tls_context.wrap_socket(
                connection_socket,
                server_side=True
            )

            print(f"Secure TLS connection established: {client_address}")

            # Pass the secure socket to the existing handler.
            client_thread = threading.Thread(
                target=handle_client,
                args=(secure_socket, client_address)
            )
            client_thread.start()

        except (ssl.SSLError, OSError) as e:
            print(f"TLS connection failed for {client_address}: {e}")
            connection_socket.close()


if __name__ == "__main__":
    start_server()