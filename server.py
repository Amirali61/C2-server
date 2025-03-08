import socket
import base64


def encode64(data):
    return base64.b64encode(data)

def decode64(data):
    return base64.b64decode(data)

conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

conn.connect(('192.168.50.200',22222))

conn.sendall(encode64(b'Hello,server'))

data = decode64(conn.recv(1024))
print(f"Received: {data.decode()}")



while 1:
    try:
        payload = input("Chi befrestam: ")
        if "del" in payload:
            conn.sendall(encode64(payload.encode()))
            result = decode64(conn.recv(1024))
            print(result.decode())
        else:
            conn.sendall(encode64(payload.encode()))
            len_chunks = decode64(conn.recv(1024)).decode()
            print(len_chunks)
            for i in range(int(len_chunks)):
                result =decode64(conn.recv(1024))
                if "download" in payload:
                    file_name = payload.split(" ")
                    with open(f"./{file_name[1]}","ab") as file:
                        file.write(result)
                print(result.decode())
    except KeyboardInterrupt:
        print("\nClosing connection")
        conn.sendall(encode64(b'close'))
        break

conn.close()

