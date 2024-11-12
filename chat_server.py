import eventlet; eventlet.monkey_patch()
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import os, hashlib, base64, json, logging, sys
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
        self.CLIENT_VERSION = "1.0.1"
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = os.urandom(32)
        self.socketio = SocketIO(self.app, logger=False, engineio_logger=False, 
                               cors_allowed_origins="*", async_mode='eventlet')
        self.host, self.port = '0.0.0.0', int(os.environ.get('PORT', 10001))
        self.active_users = {}
        self.sid_to_username = {}
        self.pending_auth = {}
        self.MAX_MSG_SIZE = 1024 * 1024
        self.setup_routes()
        self.setup_socketio()

    def hash_username(self, username):
        return hashlib.sha256(username.encode()).hexdigest()

    def derive_encryption_key(self, server_challenge, client_challenge, username, session_key):
        try:
            unique_material = f"{username}:{session_key}:{server_challenge}{client_challenge}".encode()
            session_salt = hashlib.sha256(session_key.encode()).digest()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=session_salt,
                iterations=100000,
                backend=default_backend()
            )
            return base64.urlsafe_b64encode(kdf.derive(unique_material))
        except Exception as e:
            logger.error(f"Key derivation failed: {str(e)}")
            raise

    def setup_routes(self):
        @self.app.route('/assets/data/stream', methods=['GET'])
        def health_check():
            return jsonify({'status': 'ok', 'cache-status': 'hit', 'current_version': self.CLIENT_VERSION})

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
                
                encryption_key = self.derive_encryption_key(
                    auth_data['challenge'],
                    client_challenge,
                    username,
                    session_key
                )
                
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

        @self.app.route('/api/resources/validate', methods=['POST', 'OPTIONS'])
        def authenticate():
            if request.method == 'OPTIONS':
                return jsonify({'status': 'ok'})
            try:
                username = str(request.get_json(force=True).get('username', ''))
                client_version = str(request.get_json(force=True).get('version', self.CLIENT_VERSION))
                
                if not username:
                    raise ValueError('Invalid identifier')
                
                if client_version != self.CLIENT_VERSION:
                    return jsonify({
                        'status': 'update_required',
                        'current_version': self.CLIENT_VERSION
                    }), 426

                hashed_username = self.hash_username(username)
                if hashed_username in self.active_users:
                    if 'sid' not in self.active_users[hashed_username]:
                        del self.active_users[hashed_username]
                    else:
                        raise ValueError('Identifier in use')
                
                server_challenge = base64.urlsafe_b64encode(os.urandom(32)).decode()
                session_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
                self.pending_auth[hashed_username] = {
                    'challenge': server_challenge,
                    'timestamp': datetime.now(),
                    'username': username,
                    'session_key': session_key
                }
                return jsonify({'status': 'ok', 'challenge': server_challenge, 'session_key': session_key})
            except Exception as e:
                return jsonify({'error': str(e)}), 400

    def setup_socketio(self):
        @self.socketio.on('connect')
        def handle_connect():
            pass

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
            except Exception as e:
                logger.error(f"Disconnect error: {str(e)}")

        @self.socketio.on('register')
        def handle_register(data):
            try:
                username = data.get('username')
                session_key = data.get('session_key')
                if not username:
                    raise ValueError("Invalid username")
                
                hashed_username = self.hash_username(username)
                if hashed_username in self.active_users and self.active_users[hashed_username]['session_key'] == session_key:
                    self.sid_to_username[request.sid] = hashed_username
                    self.active_users[hashed_username]['sid'] = request.sid
                    self.broadcast_user_update()
                else:
                    raise ValueError(f"Registration failed for {username}: Invalid session")
            except Exception as e:
                emit('error', {'message': str(e)}, room=request.sid)

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
                encrypted_msg = data.get('message')
                
                if not encrypted_msg:
                    raise ValueError("Empty message content")
                
                decrypted_msg = sender['fernet'].decrypt(encrypted_msg.encode()).decode()
                message_data = json.loads(decrypted_msg)
                
                # Broadcast message to all users
                for recipient_hash, recipient in self.active_users.items():
                    try:
                        if 'sid' in recipient:
                            emit('resource_update', {
                                'message': recipient['fernet'].encrypt(json.dumps(message_data).encode()).decode(),
                                'timestamp': datetime.now().isoformat()
                            }, room=recipient['sid'])
                    except:
                        continue
                        
            except Exception as e:
                emit('error', {'message': str(e)}, room=request.sid)

    def broadcast_user_update(self):
        try:
            active_streams = [data['username'] for data in self.active_users.values() if 'sid' in data]
            emit('cache_status', {'active_streams': active_streams}, broadcast=True)
        except Exception:
            pass

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
