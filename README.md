# Encrypted Remote Control Tool (Python)

This project consists of a Python-based encrypted remote access tool with basic client-server communication over TCP sockets. It uses AES encryption (from the `pycryptodome` library) to securely transmit data between the client and server.

> ⚠️ **For Educational & Research Purposes Only**
>
> Misuse of this tool can violate laws and ethical guidelines. Ensure all testing is performed on systems you own or have explicit permission to operate on.

---

## Features

### ✅ Secure Communication
- Uses AES encryption to protect all data transmitted over the network
- Multiple layers of code obfuscation and packing
- Anti-debugging and anti-VM detection mechanisms

### 🖥 Client Capabilities (`client.py`)
- File operations (`download`, `upload`, `del`, `encrypt`, `decrypt`)
- Directory and network commands (`dir`, `ipconfig`, `arp -a`, `pwd`)
- Process management (`ps`, `kill`, `system`)
- WiFi network management (`wifi-networks`, `wifi-password`)
- System information (`hostname`, `system`)
- Persistent execution using Windows Scheduled Tasks or Linux systemd
- OS detection and cross-platform support
- Chunked encrypted file transfers
- Basic authentication mechanism
- Anti-detection features:
  - VM detection
  - Debugger detection
  - Random delays
  - Code obfuscation

### 📡 Server Features (`server.py`)
- Listens for connections on port `4444`
- Handles authentication
- Sends commands to the client and handles responses
- Supports file transfer, navigation, and system command output
- Cross-platform command support

---

## How It Works

1. **Server (`server.py`)**:
    - Listens for an incoming connection
    - Receives encryption key and client OS
    - Handles encrypted interaction and command execution
    - Supports cross-platform commands

2. **Client (`client.py`)**:
    - Attempts to connect to the server at `[Your Server's IP]:4444`
    - Sends encryption key and system info
    - Waits for encrypted commands and executes them
    - Returns encrypted responses in chunks
    - Implements anti-detection measures
    - Supports both Windows and Linux systems

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

> Note: Ensure both systems have Python 3.x installed and `pycryptodome` library available.

### 3. Supported Commands
From the server interface:
```text
help                    Show available commands
dir                     List directory contents
path                    Show current working directory
ipconfig                Show network configuration
arp -a                  Display ARP table
hostname                Show system hostname and details
ps                      List running processes
kill <PID/name>         Kill a process by PID or name
system                  Show system resource usage (CPU & Memory)
wifi-networks           List available WiFi networks
wifi-password <network> Get password for a WiFi network
cd <dir>                Change directory
del <file>              Delete a file
download <file>         Download file from client
upload <file>           Upload file to client
encrypt <file>          Encrypt a file
decrypt <file>          Decrypt a file
install-task            Install persistence using Task Scheduler/systemd
uninstall-task          Remove persistence task/service
close / exit            Terminate session
```

---

## Requirements

- Python 3.x
- `pycryptodome` library:
```bash
pip install pycryptodome
```

---

## Security Features

### Anti-Detection
- VM detection with multiple indicators
- Debugger detection for both Windows and Linux
- Random delays to avoid detection
- Code obfuscation and packing

### Encryption
- AES encryption in CTR mode for all communications
- File encryption/decryption capabilities
- Chunked encrypted file transfers

### Cross-Platform Support
- Windows and Linux compatibility
- OS-specific command handling
- Platform-aware anti-detection measures

### Persistence
- Windows: Task Scheduler based persistence
- Linux: systemd service based persistence
- Automatic reconnection capabilities

---

## Disclaimer

This tool is meant **strictly for legal use**, such as:
- Penetration testing with permission
- Security research
- Educational purposes

Any unauthorized use is strictly prohibited.