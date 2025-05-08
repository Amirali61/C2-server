# Encrypted Remote Control Tool (Python)

This project consists of a Python-based encrypted remote access tool with basic client-server communication over TCP sockets. It uses symmetric encryption (Fernet from the `cryptography` library) to securely transmit data between the client and server.

> ⚠️ **For Educational & Research Purposes Only**
>
> Misuse of this tool can violate laws and ethical guidelines. Ensure all testing is performed on systems you own or have explicit permission to operate on.

---

## Features

### ✅ Secure Communication
- Uses Fernet symmetric encryption to protect all data transmitted over the network.

### 🖥 Client Capabilities (`client.py`)
- File operations (`download`, `upload`, `del`)
- Directory and network commands (`dir`, `ipconfig`, `arp -a`, `pwd`)
- Persistent execution using Windows Scheduled Tasks
- Wallpaper manipulation (Windows only)
- OS detection
- Chunked encrypted file transfers
- Basic authentication mechanism

### 📡 Server Features (`server.py`)
- Listens for connections on port `4444`
- Handles authentication
- Sends commands to the client and handles responses
- Supports file transfer, navigation, and system command output

---

## How It Works

1. **Server (`server.py`)**:
    - Listens for an incoming connection.
    - Receives encryption key and client OS.
    - Handles encrypted interaction and command execution.

2. **Client (`client.py`)**:
    - Attempts to connect to the server at `[Your Server's IP]:4444`.
    - Sends encryption key and system info.
    - Waits for encrypted commands and executes them.
    - Returns encrypted responses in chunks.

---

## Usage

### 1. Start the Server
```bash
python3 server.py
```

### 2. Start the Client
On the client machine:
```bash
python3 client.py
```

> Note: Ensure both systems have Python 3.x installed and `cryptography` library available.

### 3. Supported Commands
From the server interface:
```text
help                    Show available commands
dir                     List directory contents
path                    Show current working directory
ipconfig                Show network configuration
arp -a                  Display ARP table
cd <dir>                Change directory
del <file>              Delete a file
download <file>         Download file from client
upload <file>           Upload file to client
wall <image>            Change desktop wallpaper (Windows only)
close / exit            Terminate session
```

---

## Requirements

- Python 3.x
- `cryptography` library:
```bash
pip install cryptography
```

---

## Disclaimer

This tool is meant **strictly for legal use**, such as:
- Penetration testing with permission
- Security research
- Educational purposes

Any unauthorized use is strictly prohibited.