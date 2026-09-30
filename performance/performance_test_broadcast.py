from socket import *
import threading
import time

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

USERS = [
    ("Alice", "password123"),
    ("Bob", "bobpass"),
    ("Charlie", "charliepass"),
    ("David", "davidpass"),
    ("Eve", "evepass"),
    ("Frank", "frankpass")
]

RECIPIENTS = ["Bob", "Charlie", "David", "Eve", "Frank"]

NUMBER_OF_TRIALS = 10
BUFFER_SIZE = 4096


def login(username, password):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((SERVER_IP, SERVER_PORT))

    sock.sendall(f"LOGIN|{username}|{password}\n".encode())

    buffer = bytearray()

    while True:
        data = sock.recv(BUFFER_SIZE)

        if not data:
            raise ConnectionError("Server disconnected during login.")

        buffer.extend(data)

        if b"\n" in buffer:
            newline_index = buffer.index(b"\n")
            message = bytes(buffer[:newline_index]).decode()
            del buffer[:newline_index + 1]

            if message == "OK|LOGIN_SUCCESS":
                return sock

            raise RuntimeError(f"Login failed for {username}: {message}")


def receive_broadcast(sock, username, trial, received_times, lock):
    buffer = bytearray()

    while True:
        data = sock.recv(BUFFER_SIZE)

        if not data:
            raise ConnectionError(
                f"{username}: server disconnected."
            )

        buffer.extend(data)

        while b"\n" in buffer:
            newline_index = buffer.index(b"\n")

            message = bytes(
                buffer[:newline_index]
            ).decode()

            del buffer[:newline_index + 1]

            if message.startswith("BROADCAST|"):
                parts = message.split("|", 2)

                if (
                    len(parts) == 3
                    and parts[2] == f"Performance Test {trial}"
                ):
                    receive_time = time.perf_counter()

                    with lock:
                        received_times[username] = receive_time

                    return


def main():
    print("Connecting 6 clients...")

    clients = {}

    for username, password in USERS:
        clients[username] = login(username, password)
        print(f"{username} logged in successfully.")

    print("\nAll 6 clients connected.")
    print("Starting broadcast performance test...\n")

    results = []

    for trial in range(1, NUMBER_OF_TRIALS + 1):

        received_times = {}
        lock = threading.Lock()

        # Start one receiving thread for each recipient
        receiver_threads = []

        for username in RECIPIENTS:
            thread = threading.Thread(
                target=receive_broadcast,
                args=(
                    clients[username],
                    username,
                    trial,
                    received_times,
                    lock
                )
            )

            thread.start()
            receiver_threads.append(thread)

        time.sleep(0.1)

        # Alice sends the broadcast
        message = f"BROADCAST|Performance Test {trial}\n"

        start_time = time.perf_counter()

        clients["Alice"].sendall(message.encode())

        # Wait until all 5 recipients receive it
        for thread in receiver_threads:
            thread.join()

        end_time = max(received_times.values())

        delivery_time = (end_time - start_time) * 1000

        results.append(delivery_time)

        print(
            f"Trial {trial}: "
            f"{delivery_time:.3f} ms"
        )

        time.sleep(0.2)

    # Logout all clients
    for sock in clients.values():
        try:
            sock.sendall(b"LOGOUT\n")
        except:
            pass

        sock.close()

    average_time = sum(results) / len(results)
    minimum_time = min(results)
    maximum_time = max(results)

    print("\n========== BROADCAST RESULTS ==========")
    print(f"Number of trials : {NUMBER_OF_TRIALS}")
    print(f"Recipients       : 5")
    print(f"Average time     : {average_time:.3f} ms")
    print(f"Minimum time     : {minimum_time:.3f} ms")
    print(f"Maximum time     : {maximum_time:.3f} ms")


if __name__ == "__main__":
    main()