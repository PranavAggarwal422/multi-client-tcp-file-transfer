from socket import *
import time

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

def receive_until_msg_sent(client_socket):
    buffer = bytearray()

    while True:
        data = client_socket.recv(4096)

        if not data:
            raise ConnectionError("Server disconnected.")

        buffer.extend(data)

        while b"\n" in buffer:
            newline_index = buffer.index(b"\n")

            message = bytes(buffer[:newline_index]).decode()
            del buffer[:newline_index + 1]

            print("Received:", message)

            if message == "OK|MSG_SENT":
                return


def main():
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))

    print("Connected to server.")

    # Login as a new test user
    client_socket.sendall(b"LOGIN|David|davidpass\n")

    # Wait for login response
    buffer = bytearray()

    while True:
        data = client_socket.recv(4096)

        if not data:
            raise ConnectionError("Server disconnected.")

        buffer.extend(data)

        if b"\n" in buffer:
            newline_index = buffer.index(b"\n")
            message = bytes(buffer[:newline_index]).decode()
            del buffer[:newline_index + 1]

            print("Login response:", message)

            if message == "OK|LOGIN_SUCCESS":
                break

    # Give the server a moment to process login
    time.sleep(0.2)

    number_of_trials = 10
    rtt_values = []

    print("\nStarting RTT measurements...\n")

    for trial in range(1, number_of_trials + 1):

        message = f"MSG|Bob|RTT Test {trial}\n"

        start_time = time.perf_counter()

        client_socket.sendall(message.encode())

        receive_until_msg_sent(client_socket)

        end_time = time.perf_counter()

        rtt = (end_time - start_time) * 1000
        rtt_values.append(rtt)

        print(f"Trial {trial}: {rtt:.3f} ms")

        time.sleep(0.2)

    client_socket.close()

    average_rtt = sum(rtt_values) / len(rtt_values)
    minimum_rtt = min(rtt_values)
    maximum_rtt = max(rtt_values)

    print("\n========== RTT RESULTS ==========")
    print(f"Number of trials : {number_of_trials}")
    print(f"Average RTT      : {average_rtt:.3f} ms")
    print(f"Minimum RTT      : {minimum_rtt:.3f} ms")
    print(f"Maximum RTT      : {maximum_rtt:.3f} ms")


if __name__ == "__main__":
    main()