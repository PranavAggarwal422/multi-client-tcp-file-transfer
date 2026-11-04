# Secure Multi-Client Communication & File Transfer

A Python TCP client-server application providing TLS-protected
communication, end-to-end encrypted messaging, authenticated
client-to-client file transfer, and file-integrity verification. A
threaded server supports multiple concurrent clients.

## Overview

All client-server connections use TLS. Private messages, broadcasts, and
client-to-client file transfers add application-level end-to-end
encryption, allowing the server to relay ciphertext without reading the
payload. Uploads and downloads use TLS because the server is the
intended endpoint for those operations.

The default local server address is `127.0.0.1:5000`.

## Features

-   Salted PBKDF2-HMAC-SHA-256 password hashing (600,000 iterations;
    32-byte derived hash).
-   TLS 1.2 or newer, with server-certificate and hostname/IP
    verification.
-   End-to-end encrypted private messages (`MSG`) and broadcasts
    (`BROADCAST`).
-   End-to-end encrypted client-to-client file transfer (`SEND`).
-   RSA-PSS digital signatures for sender and payload verification.
-   SHA-256 public-key fingerprints pinned in local configuration.
-   SHA-256 file-integrity checks for transfers.
-   Threaded server supporting concurrent clients.

## Security Design

### TLS and server authentication

The server wraps accepted TCP connections using Python's `ssl` module
and loads a certificate with its matching private key. Clients are
configured to trust the expected server certificate, require certificate
verification, and check the hostname/IP. The local development setup
uses a self-signed certificate; it is not a production
certificate-management setup.

### Password storage

Each account has a unique random salt. Passwords are processed with
PBKDF2-HMAC-SHA-256. During login, the server derives a candidate hash
using the stored salt and compares it with the stored hash using
`secrets.compare_digest`. Plaintext passwords are not stored.

### End-to-end encryption

`MSG`, `BROADCAST`, and `SEND` use hybrid encryption:

1.  The sender generates a fresh AES-256 key and 12-byte nonce.
2.  AES-256-GCM encrypts the message or file package.
3.  RSA-3072 with OAEP-SHA-256 encrypts the AES key for the intended
    recipient.
4.  The encrypted envelope is sent through the TLS connection.
5.  The recipient uses their RSA private encryption key to recover the
    AES key and decrypt the payload.

Authenticated additional data (AAD) binds the encrypted payload to its
operation and sender/recipient context. A separate envelope is created
for each broadcast recipient. The server forwards encrypted envelopes
without decrypting their contents.

### Digital signatures and trusted public keys

Each client has a separate RSA signing key pair. The sender signs a
canonical representation binding the sender, recipient, operation
context, and encoded encrypted envelope using RSA-PSS with SHA-256. The
recipient verifies the signature using the sender's trusted public
signing key before decrypting or accepting the payload.

Before a peer's encryption or signing public key is used, its SHA-256
fingerprint is checked against locally pinned fingerprints in
`trusted_keys.py`.

### File transfer and integrity

-   **`UPLOAD`:** The client sends a file over TLS. The server
    calculates SHA-256 over the received bytes and compares it with the
    digest supplied by the client. A mismatch causes rejection.
-   **`DOWNLOAD`:** The server sends a stored file over TLS. The
    receiving client calculates SHA-256 and checks it against the
    expected digest.
-   **`SEND`:** The sender packages the filename, original SHA-256
    digest, and file bytes, then encrypts and signs the package for the
    recipient. The recipient verifies the signature, decrypts the
    package, checks the digest, and saves the file only after successful
    verification.

The server is the intended endpoint for `UPLOAD` and `DOWNLOAD`; those
operations use TLS rather than client-to-client E2EE. For `SEND`, the
server acts as a ciphertext relay.

The server can still observe routing metadata such as sender, recipient,
ciphertext size, and transfer timing. In the local multi-client
development setup, demo private keys may be present on the same machine
for testing. In a real deployment, each client must retain exclusive
control of its own private keys, separate from the server.

## Cryptographic Components

| Purpose | Mechanism |
|---|---|
| Client-server transport | TLS 1.2 or newer |
| Message/file-package encryption | AES-256-GCM |
| AES key wrapping | RSA-3072 OAEP with SHA-256 |
| Digital signatures | RSA-PSS with SHA-256 |
| File integrity | SHA-256 |
| Password hashing | PBKDF2-HMAC-SHA-256 |
| Public-key verification | SHA-256 fingerprints |

Each encrypted payload uses a fresh AES key and a 12-byte nonce.

## Project Structure

| File / directory | Purpose |
|---|---|
| `client.py` | Client connection, authentication, messaging, and file-transfer operations |
| `server.py` | Threaded TLS server, authentication, message routing, and file handling |
| `protocol.py` | Shared application-protocol parsing and message construction |
| `e2ee.py` | AES-GCM encryption and RSA-OAEP key wrapping |
| `key_manager.py` | RSA encryption/signing key generation and loading |
| `signature_utils.py` | Digital-signature generation and verification |
| `trusted_keys.py` | Locally pinned public-key fingerprints |
| `setup_passwords.py` | Utility for creating salted password records |
| `requirements.txt` | Python dependency specification |
| `certs/` | Server certificate and local server private key (private key is generated locally; do not commit) |
| `client_keys/` | Client private encryption/signing keys (generated locally; do not commit) |
| `trusted_public_keys/` | Client public encryption/signing keys |
| `test/` | Test certificates and file-transfer test data |
| `server_files/` | Server-side uploaded-file storage |
| `downloads/` | Client-side downloaded-file storage |

## Requirements

-   Python 3.12
-   OpenSSL
-   `cryptography==48.0.0` (see `requirements.txt`)

## Setup

**Important:** Private keys and password records are intentionally
excluded from version control. A fresh clone must be provisioned with
local credentials and keys before it can run. Do not commit private keys
or password databases.

### 1. Clone and install

``` bash
git clone <REPOSITORY_URL>
cd <REPOSITORY_DIRECTORY>
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

``` powershell
.venv\Scripts\Activate.ps1
```

**macOS / Linux**

``` bash
source .venv/bin/activate
```

Install dependencies:

``` bash
python -m pip install -r requirements.txt
```

### 2. Generate a local TLS certificate

Run from the project root:

``` bash
openssl req -x509 -newkey rsa:2048 \
  -keyout certs/server-key.pem \
  -out certs/server-cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Keep `certs/server-key.pem` private. Configure the client to trust the
matching `certs/server-cert.pem`.

### 3. Configure client keys and accounts

The application expects client encryption/signing keys, matching public
keys, trusted fingerprints, and password records to exist locally.

-   Use `key_manager.py` to create the client encryption and signing key
    material.
-   Ensure the corresponding public keys are available under
    `trusted_public_keys/`.
-   Update the pinned fingerprints in `trusted_keys.py` to match the
    public keys generated for the local users.
-   Use `setup_passwords.py` to create local salted password records in
    `password_records.json`.

The key files, pinned fingerprints, and password records must correspond
to the same local accounts. Review the setup utilities and their
prompts/configuration before running them. Do not run key or password
setup utilities during normal application startup. Replacing a key
without updating its pinned fingerprint will cause key verification to
fail.

## Run

Start the server from the project root:

``` bash
python server.py
```

In separate terminals, start one client per user:

``` bash
python client.py
```

Log in using an account configured in the local password records.
Multiple clients can connect concurrently.

## Application Commands

Control messages use a newline-terminated, pipe-separated format:

```text
COMMAND|FIELD1|FIELD2|...
```

All control messages are transmitted inside TLS.

| Operation | Command | Description |
|---|---|---|
| Login | `LOGIN|username|password` | Authenticate a user |
| List users | `LIST` | List currently online users |
| Private message | `MSG|recipient|message` | Send an end-to-end encrypted private message |
| Broadcast | `BROADCAST|message` | Send an end-to-end encrypted message to online users |
| Upload | `UPLOAD|filename` | Upload a file to the server |
| Download | `DOWNLOAD|filename` | Download a file from the server |
| Client-to-client transfer | `SEND|recipient|filename` | Send an end-to-end encrypted file through the server |
| Logout | `LOGOUT` | Log out the current user |

For `UPLOAD` and `SEND`, filenames are resolved relative to the client's
current working directory. Downloaded files are saved in `downloads/`.

## Testing

Run standalone cryptographic and integrity tests from the project root:

``` bash
python test_e2ee.py
python test_key_manager.py
python test_signatures.py
python test_signing_keys.py
python test_trusted_keys.py
python test_integrity.py
python test_send_integrity.py
```

The following tests require the server to be running in another
terminal:

``` bash
python test_upload_corruption.py
python test_tls_rejection.py
```

The development test set covers successful and failed authentication,
TLS establishment and untrusted-certificate rejection, private-message
and broadcast decryption, rejection of modified ciphertext/signatures
and incorrect sender keys, trusted-key fingerprint checks, 100 KB/1
MB/10 MB client-to-client transfers, file-integrity checks,
corrupted-upload rejection, and upload/download functionality.

## Performance Observations

The following values were recorded from local client-to-client encrypted file transfers. They are single-run server-side observations, not averages or end-to-end client transfer benchmarks.

| Original file size | Ciphertext size | Server elapsed time | Reported throughput |
|---:|---:|---:|---:|
| 100 KB | 243,760 bytes | 0.002241 s | 103.715 MiB/s |
| 1 MB | 2,486,544 bytes | 0.017858 s | 132.791 MiB/s |
| 10 MB | 24,856,164 bytes | 0.181399 s | 130.677 MiB/s |

The transmitted representation is larger than the original file because
the file package and encrypted envelope use Base64 encoding for
transport through the text-based protocol.

## Limitations and Production Considerations

-   The self-signed certificate is for local development. A deployed
    service needs an appropriate certificate lifecycle and
    trust-management process.
-   The local demo key setup is for testing. Production clients should
    generate and protect their own private keys; private keys must not
    be distributed with the server.
-   Public-key fingerprint pinning requires a secure process for
    distributing and updating trusted fingerprints.
-   The server can observe routing metadata even when message and file
    contents are end-to-end encrypted.
-   The application is configured for local testing and is not
    represented as a production-hardened internet-facing service.

## License

Add a license before distributing the project or accepting external
contributions. Until a license is selected, all rights remain with the
copyright holder.
