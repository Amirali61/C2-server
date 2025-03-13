# Remote Control Tool

## Overview

This project consists of a **client-server** architecture for remote control of a target machine. It allows an authenticated user to execute commands on the client machine from the server, retrieve system information, transfer files, and even log keystrokes.

**Disclaimer:** This tool is for educational and lab use only. Unauthorized usage is illegal and unethical.

---

## Features

- Secure communication with **AES encryption** (via `cryptography.fernet`)
- **Authentication system** for client-server connection
- Execute system commands remotely
- File transfer capabilities (upload/download)
- **Keylogger** to monitor keystrokes
- Change the target machine's **wallpaper**
- Retrieve network information (`ipconfig`, `arp -a`)

---

## Requirements

Ensure the following dependencies are installed before running the program:

```sh
pip install pynput cryptography
```

---

## Setup & Usage

### Server Setup

1. Run `server.py` on the controlling machine.
2. Enter the credentials when prompted.
3. Use the available commands to interact with the client.

```sh
python server.py
```

### Client Setup

1. Run `client.py` on the target machine.
2. It will listen for connections from the server.

```sh
python client.py
```

---

## Available Commands

| Command                      | Description                         |
| ---------------------------- | ----------------------------------- |
| `dir`                        | List files in the current directory |
| `path`                       | Show current directory path         |
| `ipconfig`                   | Show network interface details      |
| `arp -a`                     | Display ARP table                   |
| `del [file]`                 | Delete a file                       |
| `cd [path]`                  | Change directory                    |
| `download [file]`            | Download file from the client       |
| `upload [file]`              | Upload file to the client           |
| `wall [file]`                | Change the client's wallpaper       |
| `keylogger [count] [buffer]` | Log keystrokes                      |
| `help`                       | Display available commands          |
| `close`                      | Terminate the connection            |

---

## Security Considerations

- This tool should be used **only for ethical and educational purposes**.
- Ensure that the **encryption key is kept secure** to prevent unauthorized access.
- Modify the **IP address in **`` before deployment to match your network.

---

## Disclaimer

This project is intended **only for educational use** and ethical hacking practice within controlled environments. Unauthorized access to systems without permission is illegal.

