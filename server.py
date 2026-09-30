import os
from socket import *
from protocol import parse_message, make_message
import threading


SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
BACKLOG = 10
BUFFER_SIZE = 4096
SERVER_FILES_DIR = "server_files"


USERS = {
    "Alice": "password123",
    "Bob": "bobpass",
    "Charlie": "charliepass",
    "David": "davidpass",
    "Eve": "evepass",
    "Frank": "frankpass",
    "Grace": "gracepass",
    "Heidi": "heidipass",
    "Ivan": "ivanpass",
    "Judy": "judypass"
}


active_users = {}
active_users_lock = threading.Lock()


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
            print(f"Fields: {fields}")

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

                    # Check password
                    if USERS[login_username] != password:
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

            # MSG
            elif command == "MSG":
                    # User must be logged in
                    if username is None:
                        response = make_message("ERROR", "NOT_AUTHENTICATED")
                        send_message(connection_socket, send_lock, response)
                        continue

                    # MSG requires recipient and message
                    if len(fields) != 2:
                        response = make_message("ERROR", "INVALID_MSG_FORMAT")
                        send_message(connection_socket, send_lock, response)
                        continue

                    recipient = fields[0]
                    message_text = fields[1]

                    if recipient == username:
                        response = make_message("ERROR", "CANNOT_MESSAGE_SELF")
                        send_message(connection_socket, send_lock, response)
                        continue

                    # Find recipient's socket
                    with active_users_lock:
                        recipient_info = active_users.get(recipient)

                    # Recipient is not currently online
                    if recipient_info is None:
                        response = make_message("ERROR", "USER_NOT_ONLINE")
                        send_message(connection_socket, send_lock, response)
                        continue

                    recipient_socket, recipient_send_lock = recipient_info

                    # Forward message to recipient
                    forwarded_message = make_message("MSG", username, message_text)

                    try:
                        send_message(recipient_socket, recipient_send_lock, forwarded_message)
                    except Exception as e:
                        print(f"Could not send message to {recipient}. Error: {e}")
                        response = make_message("ERROR", "DELIVERY_FAILED")
                        send_message(connection_socket, send_lock, response)
                        continue

                    # Tell sender that message was delivered
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

            # BROADCAST
            elif command == "BROADCAST":
                    # User must be logged in
                    if username is None:
                        response = make_message("ERROR", "NOT_AUTHENTICATED")
                        send_message(connection_socket, send_lock, response)
                        continue

                    # BROADCAST requires exactly one field
                    if len(fields) != 1:
                        response = make_message("ERROR", "INVALID_BROADCAST_FORMAT")
                        send_message(connection_socket, send_lock, response)
                        continue

                    message_text = fields[0]

                    # Get all currently active users except the sender
                    with active_users_lock:
                        recipients = [
                            (recipient, recipient_socket, recipient_send_lock)
                            for recipient, (recipient_socket, recipient_send_lock)
                            in active_users.items()
                            if recipient != username
                        ]

                    # Create message that will be forwarded
                    forwarded_message = make_message("BROADCAST", username, message_text)
                    failed_recipients = []

                    # Send broadcast to every recipient
                    for recipient, recipient_socket, recipient_send_lock in recipients:
                        try:
                            send_message(recipient_socket, recipient_send_lock, forwarded_message)

                        except Exception as e:
                            print(f"Could not send broadcast to {recipient}. Error: {e}")
                            failed_recipients.append(recipient)


                    # Tell sender the result
                    if len(failed_recipients) == 0:
                        response = make_message("OK", "BROADCAST_SENT")

                    else:
                        failed_users = ",".join(failed_recipients)
                        response = make_message("ERROR", "BROADCAST_PARTIAL", failed_users)

                    send_message(connection_socket, send_lock, response)

            # UPLOAD
            elif command == "UPLOAD":
                if username is None:
                    response = make_message("ERROR", "NOT_AUTHENTICATED")
                    send_message(connection_socket, send_lock, response)
                    continue

                if len(fields) != 2:
                    response = make_message("ERROR", "INVALID_UPLOAD_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                filename = fields[0]

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

                try:
                    # Tell the client that the upload request was accepted.
                    response = make_message("OK", "READY_FOR_UPLOAD")
                    send_message(connection_socket, send_lock, response)

                    # Now receive the actual file data.
                    with open(file_path, "wb") as file:
                        receive_file(connection_socket,receive_buffer, file, filesize)

                    response = make_message("OK", "UPLOAD_SUCCESS")
                    send_message(connection_socket, send_lock, response)

                    print(f"User {username} uploaded {filename} ({filesize} bytes).")

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

                response = make_message("OK", "READY_FOR_DOWNLOAD", filename, str(filesize))
                
                try:
                    with send_lock:
                        connection_socket.sendall(response.encode())
                        send_file(connection_socket, file_path, filesize)
                        
                    print(
                        f"Sent {filename} ({filesize} bytes) "
                        f"to {username}."
                    )

                except Exception as e:
                    print(f"Download failed for {username}: {e}")
                    break

            # SEND
            elif command == "SEND":
                if username is None:
                    response = make_message("ERROR", "NOT_AUTHENTICATED")
                    send_message(connection_socket, send_lock, response)
                    continue

                if len(fields) != 3:
                    response = make_message("ERROR", "INVALID_SEND_FORMAT")
                    send_message(connection_socket, send_lock, response)
                    continue

                recipient = fields[0]
                filename = fields[1]

                if not filename or os.path.basename(filename) != filename:
                    response = make_message("ERROR", "INVALID_FILENAME")
                    send_message(connection_socket, send_lock, response)
                    continue

                try:
                    filesize = int(fields[2])
                except ValueError:
                    response = make_message("ERROR", "INVALID_FILESIZE")
                    send_message(connection_socket, send_lock, response)
                    continue

                if filesize < 0:
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

                try:
                    # Tell sender that server is ready
                    response = make_message("OK", "READY_FOR_SEND")
                    send_message(connection_socket, send_lock, response)

                    # Tell receiver that a file is coming
                    response = make_message("OK", "READY_FOR_RECEIVE", username, filename, str(filesize))

                    with recipient_send_lock:
                        recipient_socket.sendall(response.encode())
                        receive_and_forward_file(connection_socket, receive_buffer, recipient_socket, filename,filesize)

                    # Tell sender that transfer completed
                    response = make_message("OK", "SEND_SUCCESS")
                    send_message(connection_socket, send_lock, response)

                    print(
                        f"User {username} sent {filename} "
                        f"({filesize} bytes) to {recipient}."
                    )

                except Exception as e:
                    print(
                        f"Send failed from {username} "
                        f"to {recipient}: {e}"
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
    server_socket = socket(AF_INET, SOCK_STREAM)

    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(BACKLOG)

    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        connection_socket, client_address = server_socket.accept()

        client_thread = threading.Thread(target = handle_client, args=(connection_socket, client_address))
        client_thread.start()


if __name__ == "__main__":
    start_server()