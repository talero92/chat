import eventlet
eventlet.monkey_patch()

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import os, hashlib, base64, json, logging, sys, eventlet, secrets, threading, time
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
[logging.getLogger(name).setLevel(logging.ERROR) for name in ['werkzeug', 'socketio', 'engineio']]

class SecureChatServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = os.urandom(32)
        self.socketio = SocketIO(self.app, logger=False, engineio_logger=False, cors_allowed_origins="*", async_mode='eventlet')
        self.host, self.port = '0.0.0.0', int(os.environ.get('PORT', 10001))
        self.active_users = {}
        self.sid_to_username = {}
        self.pending_auth = {}
        self.session_keys = {}
        self.MAX_MSG_SIZE = 1024 * 1024
        self.admin_secret = secrets.token_urlsafe(16)
        self.admin_users = set()
        
        # Print admin key prominently
        self.print_admin_key()
        
        # Start a thread to periodically print the admin key
        self.start_key_printer()
        
        self.setup_routes()
        self.setup_socketio()

    def print_admin_key(self):
        key_message = """
╔════════════════════════════════════════════════════════════════╗
║                     ADMIN KEY INFORMATION                      ║
╠════════════════════════════════════════════════════════════════╣
║                                                               ║
║  Admin Secret Key: {key}                                      
║                                                               ║
║  Use this command to authenticate: /auth {key}                 
║                                                               ║
╚════════════════════════════════════════════════════════════════╝
""".format(key=self.admin_secret)
        print(key_message)
        sys.stdout.flush()

    def start_key_printer(self):
        def print_key_periodically():
            while True:
                self.print_admin_key()
                time.sleep(300)  # Print every 5 minutes
        
        thread = threading.Thread(target=print_key_periodically)
        thread.daemon = True
        thread.start()

    def generate_session_key(self): return base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    def hash_username(self, username): return hashlib.sha256(username.encode()).hexdigest()
    
    def authenticate_admin(self, username, secret):
        if secret == self.admin_secret:
            hashed_username = self.hash_username(username)
            self.admin_users.add(hashed_username)
            return True
        return False

    def is_admin(self, username): return self.hash_username(username) in self.admin_users

    def derive_encryption_key(self, server_challenge, client_challenge, username, session_key):
        try:
            unique_material = f"{username}:{session_key}:{server_challenge}{client_challenge}".encode()
            session_salt = hashlib.sha256(session_key.encode()).digest()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=session_salt, 
                            iterations=100000, backend=default_backend())
            return base64.urlsafe_b64encode(kdf.derive(unique_material))
        except Exception as e:
            logger.error(f"Key derivation failed: {str(e)}")
            raise

    def setup_routes(self):
        @self.app.route('/assets/data/stream', methods=['GET'])
        def health_check(): return jsonify({'status': 'ok', 'cache-status': 'hit'})

        @self.app.route('/api/resources/validate', methods=['POST', 'OPTIONS'])
        def authenticate():
            if request.method == 'OPTIONS': return jsonify({'status': 'ok'})
            try:
                username = str(request.get_json(force=True).get('username', ''))
                if not username: raise ValueError('Invalid identifier')
                hashed_username = self.hash_username(username)
                if hashed_username in self.active_users: raise ValueError('Identifier in use')
                server_challenge = base64.urlsafe_b64encode(os.urandom(32)).decode()
                session_key = self.generate_session_key()
                self.pending_auth[hashed_username] = {
                    'challenge': server_challenge, 'timestamp': datetime.now(),
                    'username': username, 'session_key': session_key
                }
                return jsonify({'status': 'ok', 'challenge': server_challenge, 'session_key': session_key})
            except Exception as e: return jsonify({'error': str(e)}), 400

        @self.app.route('/api/resources/complete_auth', methods=['POST'])
        def complete_authentication():
            try:
                data = request.get_json(force=True)
                username = str(data.get('username', ''))
                client_challenge = str(data.get('client_challenge', ''))
                session_key = str(data.get('session_key', ''))
                if not all([username, client_challenge, session_key]):
                    raise ValueError("Missing required authentication parameters")
                hashed_username = self.hash_username(username)
                if hashed_username not in self.pending_auth:
                    raise ValueError("No pending authentication")
                auth_data = self.pending_auth[hashed_username]
                if session_key != auth_data['session_key']:
                    raise ValueError("Invalid session")
                if (datetime.now() - auth_data['timestamp']).total_seconds() > 300:
                    del self.pending_auth[hashed_username]
                    raise ValueError("Challenge expired")
                encryption_key = self.derive_encryption_key(
                    auth_data['challenge'], client_challenge, username, session_key)
                self.active_users[hashed_username] = {
                    'connected_at': datetime.now().isoformat(),
                    'address': request.remote_addr,
                    'username': username,
                    'encryption_key': encryption_key,
                    'session_key': session_key,
                    'fernet': Fernet(encryption_key)
                }
                del self.pending_auth[hashed_username]
                return jsonify({'status': 'ok', 'message': 'Authentication complete'})
            except Exception as e:
                return jsonify({'error': str(e)}), 401

        @self.app.after_request
        def after_request(response):
            headers = {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,Authorization',
                'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS'
            }
            for k, v in headers.items(): response.headers.add(k, v)
            return response

    def setup_socketio(self):
        @self.socketio.on('connect')
        def handle_connect(): pass

        @self.socketio.on('register')
        def handle_register(data):
            try:
                username = data.get('username')
                session_key = data.get('session_key')
                if not username: raise ValueError("Invalid username")
                hashed_username = self.hash_username(username)
                if (hashed_username in self.active_users and
                        self.active_users[hashed_username]['session_key'] == session_key):
                    self.sid_to_username[request.sid] = hashed_username
                    self.active_users[hashed_username]['sid'] = request.sid
                    self.broadcast_user_update()
                else:
                    raise ValueError(f"Registration failed for {username}: Invalid session")
            except Exception as e:
                emit('error', {'message': str(e)}, room=request.sid)

        @self.socketio.on('disconnect')
        def handle_disconnect():
            try:
                sid = request.sid
                if sid in self.sid_to_username:
                    hashed_username = self.sid_to_username[sid]
                    if hashed_username in self.active_users:
                        del self.active_users[hashed_username]
                    del self.sid_to_username[sid]
                    self.broadcast_user_update()
            except Exception: pass

        @self.socketio.on('stream_data')
        def handle_message(data):
            try:
                if len(str(data)) > self.MAX_MSG_SIZE:
                    raise ValueError(f"Message exceeds size limit of {self.MAX_MSG_SIZE} bytes")
                
                sid = request.sid
                sender_hash = self.sid_to_username.get(sid)
                if not sender_hash or sender_hash not in self.active_users:
                    raise ValueError("Unauthorized message attempt")

                sender = self.active_users[sender_hash]
                if 'message' not in data: raise ValueError("No message content provided")
                
                encrypted_msg = data.get('message')
                if not encrypted_msg: raise ValueError("Empty message content")
                
                try:
                    decrypted_msg = sender['fernet'].decrypt(encrypted_msg.encode()).decode()
                    message_data = json.loads(decrypted_msg)
                except:
                    raise ValueError("Message decryption/parsing failed")

                if not isinstance(message_data, dict):
                    raise ValueError("Message must be a JSON object")
                
                if 'username' not in message_data or 'content' not in message_data:
                    raise ValueError("Message missing required fields")
                
                if message_data['username'] != sender['username']:
                    raise ValueError("Message username does not match sender")

                # Handle admin commands
                if message_data['content'].startswith('/auth '):
                    try:
                        _, secret = message_data['content'].split(' ', 1)
                        if self.authenticate_admin(message_data['username'], secret):
                            admin_msg = {'username': 'System', 'content': 'Admin privileges granted'}
                            encrypted_response = sender['fernet'].encrypt(json.dumps(admin_msg).encode()).decode()
                            emit('resource_update', {
                                'message': encrypted_response,
                                'timestamp': datetime.now().isoformat()
                            }, room=sender['sid'])
                            return
                    except: pass

                # Process admin commands
                if message_data['content'].startswith('/') and self.is_admin(message_data['username']):
                    cmd_parts = message_data['content'].split(' ', 1)
                    cmd = cmd_parts[0].lower()
                    
                    if cmd == '/kick' and len(cmd_parts) > 1:
                        target = cmd_parts[1]
                        target_hash = self.hash_username(target)
                        if target_hash in self.active_users:
                            target_sid = self.active_users[target_hash]['sid']
                            self.socketio.disconnect(target_sid)
                            return
                            
                    elif cmd == '/broadcast' and len(cmd_parts) > 1:
                        broadcast_msg = {'username': 'System', 'content': f"[Broadcast] {cmd_parts[1]}"}
                        for user_hash, user in self.active_users.items():
                            try:
                                encrypted = user['fernet'].encrypt(json.dumps(broadcast_msg).encode()).decode()
                                emit('resource_update', {
                                    'message': encrypted,
                                    'timestamp': datetime.now().isoformat()
                                }, room=user['sid'])
                            except: continue
                        return
                    
                    elif cmd == '/shutdown' and len(cmd_parts) > 1:
                        target = cmd_parts[1]
                        if target == "all":
                            shutdown_msg = {'username': 'System', 'content': 'shutdown'}
                            for user_hash, user in self.active_users.items():
                                try:
                                    encrypted = user['fernet'].encrypt(json.dumps(shutdown_msg).encode()).decode()
                                    emit('resource_update', {
                                        'message': encrypted,
                                        'timestamp': datetime.now().isoformat()
                                    }, room=user['sid'])
                                except:
                                    continue
                            return
                        else:
                            target_hash = self.hash_username(target)
                            if target_hash in self.active_users:
                                try:
                                    user = self.active_users[target_hash]
                                    shutdown_msg = {'username': 'System', 'content': 'shutdown'}
                                    encrypted = user['fernet'].encrypt(json.dumps(shutdown_msg).encode()).decode()
                                    emit('resource_update', {
                                        'message': encrypted,
                                        'timestamp': datetime.now().isoformat()
                                    }, room=user['sid'])
                                except:
                                    pass
                            return

                # Regular message broadcasting
                broadcast_failures = []
                for recipient_hash, recipient in self.active_users.items():
                    try:
                        recipient_encrypted = recipient['fernet'].encrypt(
                            json.dumps(message_data).encode()
                        ).decode()
                        emit('resource_update', {
                            'message': recipient_encrypted,
                            'timestamp': datetime.now().isoformat()
                        }, room=recipient['sid'])
                    except Exception:
                        broadcast_failures.append(recipient['username'])

            except ValueError as e:
                emit('error', {'message': str(e)}, room=request.sid)
            except Exception as e:
                emit('error', {'message': str(e)}, room=request.sid)

    def broadcast_user_update(self):
        try:
            active_streams = [data['username'] for data in self.active_users.values()]
            emit('cache_status', {'active_streams': active_streams}, broadcast=True)
        except Exception: pass

    def run(self):
        try:
            self.socketio.run(self.app, host=self.host, port=self.port)
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
            raise

if __name__ == '__main__':
    server = SecureChatServer()
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)
