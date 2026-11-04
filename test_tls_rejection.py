import os
import ssl
import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
TRUSTED_CERT = os.path.join(
    PROJECT_DIR, "certs", "server-cert.pem"
)
UNTRUSTED_CERT = os.path.join(
    PROJECT_DIR, "test", "certs", "untrusted-cert.pem"
)


def main():
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=UNTRUSTED_CERT,
    )
    context.check_hostname = True

    try:
        with socket.create_connection(
            (SERVER_IP, SERVER_PORT), timeout=5
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=SERVER_IP
            ):
                print("FAIL: Untrusted certificate was accepted.")

    except ssl.SSLCertVerificationError as error:
        print("PASS: Untrusted certificate was rejected.")
        print(f"Verification error: {error}")

    except (ConnectionError, TimeoutError, OSError) as error:
        print(f"INCONCLUSIVE: Connection failed before verification: {error}")


if __name__ == "__main__":
    main()