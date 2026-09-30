# Multi-Client TCP Messaging & File Transfer

A multi-client TCP client-server application built in Python. The project implements a custom application-layer protocol for authentication, messaging, broadcasting, file upload/download, and client-to-client file transfer.

## Features

- Multi-client TCP server using one thread per client connection
- Username/password authentication
- Active-user tracking with duplicate-login prevention
- Private messaging between clients
- Broadcast messaging
- File upload to the server
- File download from the server
- Client-to-client file transfer through the server
- Custom application-layer protocol
- TCP receive buffering for message framing
- Per-client send locks for safe concurrent socket writes
- Performance benchmarks for messaging, broadcasting, and concurrent file transfers

## Architecture
The server creates a separate thread for every accepted TCP connection. Logged-in users are maintained in an active-user table. Each active user is associated with a socket and a dedicated send lock.

## Custom Application-Layer Protocol

The application uses a custom text-based protocol over TCP.

### Message Format

Control messages follow:

```text
COMMAND|FIELD1|FIELD2|...\n
```

- `|` is the field separator.
- `\n` marks the end of a control message.
- Protocol fields such as usernames and filenames cannot contain the reserved separator or newline.

Examples:

```text
LOGIN|Alice|password123
LIST
MSG|Bob|Hello Bob!
BROADCAST|Hello everyone!
LOGOUT
```

### Commands

| Command | Format | Description |
|---|---|---|
| `LOGIN` | `LOGIN|user|password` | Authenticate a client |
| `LIST` | `LIST` | List currently active users |
| `MSG` | `MSG|recipient|message` | Send a message to one user |
| `BROADCAST` | `BROADCAST|message` | Send a message to all other active users |
| `UPLOAD` | `UPLOAD|filename|filesize` | Upload a file to the server |
| `DOWNLOAD` | `DOWNLOAD|filename` | Download a file from the server |
| `SEND` | `SEND|recipient|filename|filesize` | Transfer a file to another active client |
| `LOGOUT` | `LOGOUT` | End the client session |

### Responses

Successful operations use the `OK` prefix:

```text
OK|LOGIN_SUCCESS
OK|MSG_SENT
OK|BROADCAST_SENT
OK|UPLOAD_SUCCESS
```

Errors use the `ERROR` prefix:

```text
ERROR|INVALID_CREDENTIALS
ERROR|USER_NOT_ONLINE
ERROR|FILE_NOT_FOUND
ERROR|INVALID_FILENAME
ERROR|INVALID_FILESIZE
```

A TCP connection represents one client session and can have at most one authenticated username at a time.

## File Transfer Protocol

Binary file data is handled separately from control messages. The protocol includes the exact file size in the control header so the receiver knows exactly how many raw bytes belong to the file.

### Upload

```text
Client -> Server:
UPLOAD|filename|filesize

Server -> Client:
OK|READY_FOR_UPLOAD

Client -> Server:
<exactly filesize raw bytes>

Server -> Client:
OK|UPLOAD_SUCCESS
```

The server stores uploaded files in its `server_files` directory.

### Download

```text
Client -> Server:
DOWNLOAD|filename

Server -> Client:
OK|READY_FOR_DOWNLOAD|filename|filesize

Server -> Client:
<exactly filesize raw bytes>
```

The client saves downloaded files in its `downloads` directory.

### Client-to-Client File Transfer

Files can be transferred between two active clients through the server without permanently storing the file on the server.

```text
Sender -> Server:
SEND|recipient|filename|filesize

Server -> Sender:
OK|READY_FOR_SEND

Server -> Receiver:
OK|READY_FOR_RECEIVE|sender|filename|filesize

Sender -> Server:
<exactly filesize raw bytes>

Server -> Receiver:
<exactly filesize raw bytes>

Server -> Sender:
OK|SEND_SUCCESS
```

The server streams the file from the sender to the receiver in chunks.

## TCP Stream Handling

TCP provides a reliable ordered byte stream, but it does not preserve application-level message boundaries.

For example, one `recv()` call may contain:

- part of a message,
- exactly one message, or
- multiple messages.

The server and client therefore maintain receive buffers. Incoming bytes are appended to the buffer, and complete control messages are extracted whenever `\n` is found.

For file transfers, the declared file size is used to consume exactly the required number of bytes.

## Concurrent Socket Writes

Multiple server threads can need to write to the same client socket at the same time.

Without synchronization, a normal message could be inserted between a file-transfer header and its binary data.

To prevent this, every active client has a dedicated send lock.

For a file transfer, the lock covers the complete:

```text
control header + file bytes
```

sequence. This keeps a file transfer atomic with respect to other server-to-client messages.

## Performance

All benchmarks were performed locally using:

- Python on Windows
- IPv4 TCP
- Server: `127.0.0.1`
- Port: `5000`

### 1. Message RTT

10 trials were performed by sending a message through the server and measuring the time until the sender received the acknowledgement.

| Metric | Result |
|---|---:|
| Trials | 10 |
| Average RTT | 1.211 ms |
| Minimum RTT | 0.544 ms |
| Maximum RTT | 1.965 ms |

### 2. Broadcast Delivery

One sender broadcast a message to five other connected clients. The measured time was from sending the broadcast until the last recipient received it.

| Metric | Result |
|---|---:|
| Recipients | 5 |
| Trials | 10 |
| Average delivery time | 1.616 ms |
| Minimum delivery time | 0.667 ms |
| Maximum delivery time | 2.474 ms |

### 3. Concurrent File Transfer

Ten clients concurrently requested the same file from the server.

Aggregate throughput was calculated as:

```text
Throughput = (10 × File Size) / Completion Time
```

where completion time is the time until the slowest of the ten clients finishes receiving the file.

| File Size | Average Time | Average Throughput | Clients |
|---|---:|---:|---:|
| 1 MB | 0.065 s | 170.53 MB/s | 10 |
| 100 MB | 4.761 s | 210.33 MB/s | 10 |
| 1 GB | 80.482 s | 129.03 MB/s | 10 |

The 1 GB workload showed lower throughput and greater variation between trials in the local test environment.

The benchmark scripts are available in the `performance/` directory.

## Project Structure

```text
multi-client-tcp-file-transfer/
│
├── server.py
├── client.py
├── protocol.py
│
├── performance/
│   ├── performance_test_rtt.py
│   ├── performance_test_broadcast.py
│   └── performance_test_file_transfer.py
│
├── README.md
├── .gitignore
└── LICENSE
```

## Requirements

- Python 3.x
- No external Python packages are required.

## How to Run

### 1. Start the server

```bash
python server.py
```

The server listens on:

```text
127.0.0.1:5000
```

### 2. Start clients

Open separate terminals and run:

```bash
python client.py
```

Multiple clients can be started simultaneously.

### 3. Login

The project includes ten test accounts:

```text
Alice
Bob
Charlie
David
Eve
Frank
Grace
Heidi
Ivan
Judy
```

The passwords are defined in `server.py`.

### 4. Example commands

```text
LOGIN|Alice|password
LIST
MSG|Bob|Hello Bob!
BROADCAST|Hello everyone!
UPLOAD|example.pdf
DOWNLOAD|example.pdf
SEND|Bob|example.pdf
LOGOUT
```

## Performance Tests

The benchmark scripts are kept separately under `performance/`.

```bash
python performance/performance_test_rtt.py
python performance/performance_test_broadcast.py
python performance/performance_test_file_transfer.py
```

The file-transfer benchmark generates temporary test files during execution. These generated files are intentionally excluded from the repository.

## Design Highlights

### Thread-per-client

Each accepted TCP connection is handled by a separate server thread, allowing multiple clients to communicate concurrently.

### Shared active-user state

The server maintains the currently logged-in users in a shared dictionary protected by a lock.

### TCP framing

Newline-delimited control messages and explicit file-size framing are used to distinguish application messages and binary file data over TCP.

### Per-client send locks

A separate lock for each active client prevents concurrent server threads from corrupting the byte stream sent to that client.

### Streaming client-to-client transfers

For `SEND`, the server forwards file chunks directly from the sender to the receiver instead of permanently storing the transferred file.

## Future Improvements

- GUI client using PyQt/PySide
- Persistent user accounts and chat history
- Password hashing
- TLS encryption
- Message timestamps and delivery status
- Offline message support
- Group chats
- File-transfer progress indicators
- LAN and cloud/VPS deployment
- More extensive performance testing on real networks

## AI Usage

AI tools were used as development assistance for understanding networking concepts, debugging, and exploring implementation approaches.

Examples of areas where AI assistance was used:

- TCP message framing and receive buffers
- Concurrent socket writes and synchronization
- File-transfer framing using file sizes
- Debugging socket communication and edge cases

The implementation was manually tested using multiple clients and the included performance benchmarks.
