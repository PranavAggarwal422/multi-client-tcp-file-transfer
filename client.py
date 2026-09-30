from socket import *
import os, threading
from protocol import parse_message, make_message


SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
BUFFER_SIZE = 4096
DOWNLOAD_DIR = "downloads"

connection_closed = threading.Event()

upload_event = threading.Event()
upload_result = None
upload_waiting = False

download_event = threading.Event()
download_result = None
download_filename = None
download_filesize = 0



def send_file(client_socket, filename):
    global upload_result
    global upload_waiting

    if not os.path.isfile(filename):
        print(f"\nFile not found: {filename}")
        return

    filesize = os.path.getsize(filename)
    header = make_message("UPLOAD", os.path.basename(filename), str(filesize))

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

    if not os.path.isfile(filename):
        print(f"\nFile not found: {filename}")
        return

    filesize = os.path.getsize(filename)

    header = make_message("SEND",recipient, os.path.basename(filename), str(filesize))
    upload_event.clear()
    upload_result = None
    upload_waiting = True

    client_socket.sendall(header.encode())

    print(
        f"\nSend request sent for {filename} "
        f"({filesize} bytes) to {recipient}."
    )

    if not upload_event.wait(10):
        upload_waiting = False
        print("\nSend request timed out.")
        return

    upload_waiting = False

    if upload_result != "READY":
        print("\nServer did not accept the send request.")
        return

    with open(filename, "rb") as file:
        while True:
            chunk = file.read(BUFFER_SIZE)
            if not chunk:
                break

            client_socket.sendall(chunk)

    print("\nFile data sent to server.")


def handle_server_message(message):
    global upload_result
    command, fields = parse_message(message)
    

    if command == "OK":
        if len(fields) == 0:
            print("\nServer: OK")
            return

        operation = fields[0]

        if operation == "LOGIN_SUCCESS":
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
        if len(fields) == 2:
            sender = fields[0]
            message_text = fields[1]

            print(f"\n{sender}: {message_text}")

        else:
            print("\nInvalid MSG received from server.")

    elif command == "BROADCAST":
        if len(fields) == 2:
            sender = fields[0]
            message_text = fields[1]

            print(f"\n{sender} [Broadcast]: {message_text}")

        else:
            print("\nInvalid BROADCAST received from server.")

    else:
        print(f"\nUnknown server message: {message}")

def receive_download_file(client_socket, receive_buffer, filename, filesize):
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

        print(
            f"\nDownload successful: {filename} "
            f"({filesize} bytes)"
        )

    except Exception as e:
        print(f"\nDownload failed: {e}")

def receive_sent_file(client_socket, receive_buffer, sender, filename, filesize):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    file_path = os.path.join(DOWNLOAD_DIR, filename)

    received = 0

    try:
        with open(file_path, "wb") as file:
            # First consume any file bytes already in the buffer
            if receive_buffer:
                bytes_to_write = min(len(receive_buffer), filesize)
                file.write(receive_buffer[:bytes_to_write])
                del receive_buffer[:bytes_to_write]

                received += bytes_to_write

            # Receive remaining bytes
            while received < filesize:
                bytes_to_receive = min(BUFFER_SIZE, filesize - received)
                chunk = client_socket.recv(bytes_to_receive)

                if not chunk:
                    raise ConnectionError("Sender disconnected during file transfer.")

                file.write(chunk)
                received += len(chunk)

        print(
            f"\nFile received from {sender}: "
            f"{filename} ({filesize} bytes)"
        )

    except Exception as e:
        print(f"\nFile receive failed: {e}")


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
                if(command == "OK" and len(fields) >= 3 and fields[0] == "READY_FOR_DOWNLOAD"):
                    filename = fields[1]
                    filesize = int(fields[2])

                    print(
                        f"\nStarting download of {filename} "
                        f"({filesize} bytes)..."
                    )

                    receive_download_file(client_socket, receive_buffer, filename, filesize)

                elif command == "OK" and len(fields) >= 4 and fields[0] == "READY_FOR_RECEIVE":
                    sender = fields[1]
                    filename = fields[2]
                    filesize = int(fields[3])

                    print(
                        f"\nReceiving {filename} ({filesize} bytes) "
                        f"from {sender}..."
                    )

                    receive_sent_file(client_socket, receive_buffer, sender, filename, filesize)

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
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))

    print("Connected to server.")

    # Start thread to continuously receive messages
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    # Main thread handles keyboard input
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

        else:
            client_socket.sendall((command + "\n").encode())

    client_socket.close()


if __name__ == "__main__":
    start_client()

    