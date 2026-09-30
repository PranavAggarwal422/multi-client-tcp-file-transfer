from socket import *
import os
import threading
import time
import statistics


# ============================================================
# CONFIGURATION
# ============================================================

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

NUMBER_OF_CLIENTS = 10
NUMBER_OF_TRIALS = 3

BUFFER_SIZE = 64 * 1024

SERVER_FILES_DIR = "server_files"
BENCHMARK_DOWNLOAD_DIR = "benchmark_downloads"


# 10 unique users
USERS = [
    ("Alice", "password123"),
    ("Bob", "bobpass"),
    ("Charlie", "charliepass"),
    ("David", "davidpass"),
    ("Eve", "evepass"),
    ("Frank", "frankpass"),
    ("Grace", "gracepass"),
    ("Heidi", "heidipass"),
    ("Ivan", "ivanpass"),
    ("Judy", "judypass")
]


# Files to test
TEST_FILES = [
    ("test_1MB.bin", 1 * 1024 * 1024),
    ("test_100MB.bin", 100 * 1024 * 1024),
    ("test_1GB.bin", 1 * 1024 * 1024 * 1024)
]


# ============================================================
# FILE GENERATION
# ============================================================

def generate_test_file(filename, filesize):
    """
    Generate a file of exactly 'filesize' bytes.
    """

    os.makedirs(SERVER_FILES_DIR, exist_ok=True)

    file_path = os.path.join(SERVER_FILES_DIR, filename)

    # If file already exists with correct size, don't regenerate it
    if os.path.isfile(file_path):
        existing_size = os.path.getsize(file_path)

        if existing_size == filesize:
            print(
                f"[OK] {filename} already exists "
                f"({existing_size:,} bytes)"
            )
            return

    print(
        f"[GENERATING] {filename} "
        f"({filesize / (1024 * 1024):.0f} MB)"
    )

    chunk_size = 1024 * 1024

    # 1 MB chunk
    chunk = b"0" * chunk_size

    with open(file_path, "wb") as file:

        remaining = filesize

        while remaining > 0:

            bytes_to_write = min(chunk_size, remaining)

            file.write(chunk[:bytes_to_write])

            remaining -= bytes_to_write

    actual_size = os.path.getsize(file_path)

    if actual_size != filesize:
        raise RuntimeError(
            f"File size mismatch for {filename}. "
            f"Expected {filesize}, got {actual_size}."
        )

    print(
        f"[OK] Generated {filename} "
        f"({actual_size:,} bytes)"
    )


def generate_all_test_files():
    print("\n==========================================")
    print("STEP 1: GENERATING TEST FILES")
    print("==========================================\n")

    for filename, filesize in TEST_FILES:
        generate_test_file(filename, filesize)

    print("\nAll test files are ready.\n")


# ============================================================
# PROTOCOL RECEIVING
# ============================================================

def receive_line(sock):
    """
    Receive one newline-terminated protocol message.
    """

    buffer = bytearray()

    while b"\n" not in buffer:

        data = sock.recv(BUFFER_SIZE)

        if not data:
            raise ConnectionError(
                "Server disconnected while receiving message."
            )

        buffer.extend(data)

    newline_index = buffer.index(b"\n")

    message = bytes(
        buffer[:newline_index]
    ).decode()

    # Return any bytes that arrived after the newline too.
    remaining = bytes(
        buffer[newline_index + 1:]
    )

    return message, remaining


# ============================================================
# LOGIN
# ============================================================

def login(username, password):

    sock = socket(AF_INET, SOCK_STREAM)

    sock.connect(
        (SERVER_IP, SERVER_PORT)
    )

    login_message = (
        f"LOGIN|{username}|{password}\n"
    )

    sock.sendall(
        login_message.encode()
    )

    message, remaining = receive_line(sock)

    if message != "OK|LOGIN_SUCCESS":
        sock.close()

        raise RuntimeError(
            f"Login failed for {username}: {message}"
        )

    print(
        f"[LOGIN] {username} connected successfully."
    )

    return sock


# ============================================================
# RECEIVE FILE
# ============================================================

def receive_file(sock, filename, filesize, client_number):

    # Use NUL on Windows so client-side disk writing
    # does not dominate the server throughput measurement.
    if os.name == "nt":
        output_path = "NUL"
    else:
        output_path = "/dev/null"

    received = 0

    with open(output_path, "wb") as output_file:

        while received < filesize:

            bytes_to_receive = min(
                BUFFER_SIZE,
                filesize - received
            )

            data = sock.recv(
                bytes_to_receive
            )

            if not data:
                raise ConnectionError(
                    f"Client {client_number}: "
                    f"server disconnected during file transfer."
                )

            output_file.write(data)

            received += len(data)

    return received


# ============================================================
# ONE CLIENT DOWNLOAD
# ============================================================

def download_client(
    client_number,
    sock,
    filename,
    expected_size,
    start_barrier,
    results,
    results_lock
):

    try:

        # Make all 10 clients reach this point
        # before starting the transfer.
        start_barrier.wait()

        start_time = time.perf_counter()

        request = (
            f"DOWNLOAD|{filename}\n"
        )

        sock.sendall(
            request.encode()
        )

        # Receive server response
        message, remaining = receive_line(sock)

        parts = message.split("|")

        if (
            len(parts) != 4
            or parts[0] != "OK"
            or parts[1] != "READY_FOR_DOWNLOAD"
        ):
            raise RuntimeError(
                f"Unexpected server response: {message}"
            )

        received_filename = parts[2]
        filesize = int(parts[3])

        if received_filename != filename:
            raise RuntimeError(
                f"Expected {filename}, "
                f"got {received_filename}"
            )

        if filesize != expected_size:
            raise RuntimeError(
                f"Expected file size {expected_size}, "
                f"got {filesize}"
            )

        # Important:
        # 'remaining' contains binary bytes that may have
        # arrived together with the header.
        received = 0

        if remaining:

            bytes_to_write = min(
                len(remaining),
                filesize
            )

            if os.name == "nt":
                output_path = "NUL"
            else:
                output_path = "/dev/null"

            with open(output_path, "wb") as output_file:

                output_file.write(
                    remaining[:bytes_to_write]
                )

            received += bytes_to_write

        # Continue receiving remaining file bytes.
        if received < filesize:

            if os.name == "nt":
                output_path = "NUL"
            else:
                output_path = "/dev/null"

            with open(output_path, "wb") as output_file:

                while received < filesize:

                    bytes_to_receive = min(
                        BUFFER_SIZE,
                        filesize - received
                    )

                    data = sock.recv(
                        bytes_to_receive
                    )

                    if not data:
                        raise ConnectionError(
                            "Server disconnected during download."
                        )

                    output_file.write(data)

                    received += len(data)

        end_time = time.perf_counter()

        elapsed = end_time - start_time

        with results_lock:
            results[client_number] = {
                "bytes": received,
                "time": elapsed
            }

    except Exception as error:

        with results_lock:
            results[client_number] = {
                "error": str(error)
            }


# ============================================================
# ONE PERFORMANCE TRIAL
# ============================================================

def run_trial(clients, filename, filesize, trial_number):

    print(
        f"\nTrial {trial_number}: "
        f"{filename}"
    )

    results = {}

    results_lock = threading.Lock()

    start_barrier = threading.Barrier(
        NUMBER_OF_CLIENTS
    )

    threads = []

    # Create one download thread per client
    for client_number in range(
        NUMBER_OF_CLIENTS
    ):

        thread = threading.Thread(
            target=download_client,
            args=(
                client_number,
                clients[client_number],
                filename,
                filesize,
                start_barrier,
                results,
                results_lock
            )
        )

        threads.append(thread)

    # Start all client threads
    for thread in threads:
        thread.start()

    # Wait for all 10 clients
    for thread in threads:
        thread.join()

    # Check for errors
    for client_number in range(
        NUMBER_OF_CLIENTS
    ):

        result = results.get(
            client_number
        )

        if result is None:
            raise RuntimeError(
                f"Client {client_number + 1} "
                f"did not produce a result."
            )

        if "error" in result:
            raise RuntimeError(
                f"Client {client_number + 1} "
                f"failed: {result['error']}"
            )

    # --------------------------------------------------------
    # Calculate wall-clock completion time
    # --------------------------------------------------------

    # Every client starts at approximately the same time.
    # The slowest client determines when the complete
    # server-to-10-client transfer is finished.
    completion_time = max(
        result["time"]
        for result in results.values()
    )

    total_bytes = (
        filesize * NUMBER_OF_CLIENTS
    )

    throughput_MBps = (
        total_bytes / completion_time
    ) / (1024 * 1024)

    throughput_Mbps = (
        total_bytes * 8
        / completion_time
    ) / (1024 * 1024)

    print(
        f"  Total data transferred : "
        f"{total_bytes / (1024 * 1024):,.0f} MB"
    )

    print(
        f"  Completion time        : "
        f"{completion_time:.3f} seconds"
    )

    print(
        f"  Aggregate throughput   : "
        f"{throughput_MBps:.2f} MB/s"
    )

    print(
        f"  Aggregate throughput   : "
        f"{throughput_Mbps:.2f} Mbps"
    )

    return {
        "trial": trial_number,
        "time": completion_time,
        "throughput_MBps": throughput_MBps,
        "throughput_Mbps": throughput_Mbps
    }


# ============================================================
# RUN FILE SIZE TEST
# ============================================================

def run_file_test(clients, filename, filesize):

    print("\n------------------------------------------")
    print(
        f"Testing {filename} "
        f"({filesize / (1024 * 1024):,.0f} MB)"
    )
    print("------------------------------------------")

    trial_results = []

    for trial_number in range(
        1,
        NUMBER_OF_TRIALS + 1
    ):

        result = run_trial(
            clients,
            filename,
            filesize,
            trial_number
        )

        trial_results.append(result)

        # Small pause between trials
        time.sleep(1)

    throughputs = [
        result["throughput_MBps"]
        for result in trial_results
    ]

    times = [
        result["time"]
        for result in trial_results
    ]

    average_throughput = statistics.mean(
        throughputs
    )

    minimum_throughput = min(
        throughputs
    )

    maximum_throughput = max(
        throughputs
    )

    average_time = statistics.mean(
        times
    )

    return {
        "filename": filename,
        "filesize": filesize,
        "results": trial_results,
        "average_time": average_time,
        "average_throughput": average_throughput,
        "minimum_throughput": minimum_throughput,
        "maximum_throughput": maximum_throughput
    }


# ============================================================
# LOGOUT
# ============================================================

def close_clients(clients):

    print("\nClosing benchmark clients...")

    for sock in clients:

        try:
            sock.sendall(
                b"LOGOUT\n"
            )
        except:
            pass

        try:
            sock.close()
        except:
            pass

    print("All benchmark clients closed.")


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")
    print("==========================================")
    print(" PERFORMANCE TEST 3")
    print(" 10 CLIENT FILE TRANSFER BENCHMARK")
    print("==========================================")

    # --------------------------------------------------------
    # 1. Generate files
    # --------------------------------------------------------

    generate_all_test_files()

    # --------------------------------------------------------
    # 2. Connect 10 clients
    # --------------------------------------------------------

    print("==========================================")
    print("STEP 2: CONNECTING 10 CLIENTS")
    print("==========================================\n")

    clients = []

    try:

        for username, password in USERS:

            sock = login(
                username,
                password
            )

            clients.append(sock)

        print(
            f"\n[OK] "
            f"{len(clients)} clients connected."
        )

        # ----------------------------------------------------
        # 3. Run tests
        # ----------------------------------------------------

        all_results = []

        for filename, filesize in TEST_FILES:

            result = run_file_test(
                clients,
                filename,
                filesize
            )

            all_results.append(result)

        # ----------------------------------------------------
        # 4. Final results
        # ----------------------------------------------------

        print("\n\n")
        print("==========================================")
        print(" FINAL PERFORMANCE RESULTS")
        print("==========================================")

        print(
            f"{'File':<18}"
            f"{'Size':>10}"
            f"{'Avg Time':>15}"
            f"{'Avg Throughput':>20}"
        )

        print("-" * 65)

        for result in all_results:

            size_MB = (
                result["filesize"]
                / (1024 * 1024)
            )

            print(
                f"{result['filename']:<18}"
                f"{size_MB:>10.0f} MB"
                f"{result['average_time']:>14.3f} s"
                f"{result['average_throughput']:>17.2f} MB/s"
            )

        print("\n")
        print("Detailed results:")
        print()

        for result in all_results:

            print(
                f"{result['filename']}:"
            )

            for trial in result["results"]:

                print(
                    f"  Trial {trial['trial']}: "
                    f"{trial['time']:.3f} s, "
                    f"{trial['throughput_MBps']:.2f} MB/s"
                )

            print(
                f"  Average: "
                f"{result['average_throughput']:.2f} MB/s"
            )

            print(
                f"  Minimum: "
                f"{result['minimum_throughput']:.2f} MB/s"
            )

            print(
                f"  Maximum: "
                f"{result['maximum_throughput']:.2f} MB/s"
            )

            print()

    finally:

        if clients:
            close_clients(clients)

    print("\n==========================================")
    print(" PERFORMANCE TEST 3 COMPLETE")
    print("==========================================\n")


if __name__ == "__main__":
    main()