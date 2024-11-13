import eventlet; eventlet.monkey_patch()
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import os, hashlib, base64, json, secrets
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class SecureChatServer:
    def __init__(self):
        self.CLIENT_VERSION = "1.0.2"
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = os.urandom(32)
        self.socketio = SocketIO(self.app, logger=False, engineio_logger=False, cors_allowed_origins="*", async_mode='eventlet')
        self.host, self.port = '0.0.0.0', int(os.environ.get('PORT', 10001))
        self.active_users, self.sid_to_username, self.pending_auth = {}, {}, {}
        self.MAX_MSG_SIZE = 1024 * 1024
        self.admin_key = secrets.token_urlsafe(16)
        self.admin_users = set()
        print(f"\n[*] Admin Key Generated: {self.admin_key}\n")
        self.setup_routes()
        self.setup_socketio()

    def hash_username(self, username): return hashlib.sha256(username.encode()).hexdigest()

    def derive_encryption_key(self, server_challenge, client_challenge, username, session_key):
        try:
            unique_material = f"{username}:{session_key}:{server_challenge}{client_challenge}".encode()
            session_salt = hashlib.sha256(session_key.encode()).digest()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=session_salt, iterations=100000, backend=default_backend())
            return base64.urlsafe_b64encode(kdf.derive(unique_material))
        except: raise

    def setup_routes(self):
        @self.app.route('/assets/data/stream', methods=['GET'])
        def health_check(): return jsonify({'status':'ok', 'cache-status':'hit', 'current_version':self.CLIENT_VERSION})

        @self.app.route('/api/resources/complete_auth', methods=['POST'])
        def complete_authentication():
            try:
                data = request.get_json(force=True)
                username, client_challenge, session_key = str(data.get('username','')), str(data.get('client_challenge','')), str(data.get('session_key',''))
                if not all([username, client_challenge, session_key]): return jsonify({'error':'Invalid parameters'}), 401
                hashed_username = self.hash_username(username)
                if hashed_username not in self.pending_auth: return jsonify({'error':'No pending auth'}), 401
                auth_data = self.pending_auth[hashed_username]
                if session_key != auth_data['session_key']: return jsonify({'error':'Invalid session'}), 401
                encryption_key = self.derive_encryption_key(auth_data['challenge'], client_challenge, username, session_key)
                self.active_users[hashed_username] = {
                    'connected_at': datetime.now().isoformat(),
                    'address': request.remote_addr,
                    'username': username,
                    'encryption_key': encryption_key,
                    'session_key': session_key,
                    'fernet': Fernet(encryption_key)
                }
                del self.pending_auth[hashed_username]
                return jsonify({'status':'ok'})
            except: return jsonify({'error':'Auth failed'}), 401

        @self.app.route('/api/resources/validate', methods=['POST'])
        def authenticate():
            try:
                data = request.get_json(force=True)
                username, client_version = str(data.get('username','')), str(data.get('version',self.CLIENT_VERSION))
                if not username: return jsonify({'error':'Invalid username'}), 400
                if client_version != self.CLIENT_VERSION: return jsonify({'status':'update_required','current_version':self.CLIENT_VERSION}), 426
                hashed_username = self.hash_username(username)
                if hashed_username in self.active_users:
                    if 'sid' not in self.active_users[hashed_username]: del self.active_users[hashed_username]
                    else: return jsonify({'error':'Username in use'}), 400
                server_challenge = base64.urlsafe_b64encode(os.urandom(32)).decode()
                session_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
                self.pending_auth[hashed_username] = {
                    'challenge': server_challenge,
                    'timestamp': datetime.now(),
                    'username': username,
                    'session_key': session_key
                }
                return jsonify({'status':'ok', 'challenge':server_challenge, 'session_key':session_key})
            except: return jsonify({'error':'Auth failed'}), 400

    def setup_socketio(self):
        @self.socketio.on('connect')
        def handle_connect(): pass

        @self.socketio.on('disconnect')
        def handle_disconnect():
            try:
                sid = request.sid
                if sid in self.sid_to_username:
                    hashed_username = self.sid_to_username[sid]
                    if hashed_username in self.active_users:
                        username = self.active_users[hashed_username]['username']
                        if username in self.admin_users: self.admin_users.remove(username)
                        del self.active_users[hashed_username]
                    del self.sid_to_username[sid]
                    self.broadcast_user_update()
            except: pass

        @self.socketio.on('register')
        def handle_register(data):
            try:
                username, session_key = data.get('username'), data.get('session_key')
                if not username: return
                hashed_username = self.hash_username(username)
                if hashed_username in self.active_users and self.active_users[hashed_username]['session_key'] == session_key:
                    self.sid_to_username[request.sid] = hashed_username
                    self.active_users[hashed_username]['sid'] = request.sid
                    self.broadcast_user_update()
            except: pass

        @self.socketio.on('auth_admin')
        def handle_admin_auth(data):
            try:
                sid = request.sid
                sender_hash = self.sid_to_username.get(sid)
                if not sender_hash or sender_hash not in self.active_users: return
                sender = self.active_users[sender_hash]
                key = data.get('key','')
                if key == self.admin_key:
                    self.admin_users.add(sender['username'])
                    message_data = {'username':'SYSTEM','content':'Admin privileges granted!','timestamp':datetime.now().isoformat(),'type':'system'}
                else:
                    message_data = {'username':'SYSTEM','content':'Invalid admin key!','timestamp':datetime.now().isoformat(),'type':'system'}
                encrypted = sender['fernet'].encrypt(json.dumps(message_data).encode()).decode()
                emit('resource_update', {'message':encrypted,'timestamp':datetime.now().isoformat()})
            except: pass

        @self.socketio.on('admin_command')
        def handle_admin_command(data):
            try:
                sid = request.sid
                sender_hash = self.sid_to_username.get(sid)
                if not sender_hash or sender_hash not in self.active_users: return
                sender = self.active_users[sender_hash]
                if sender['username'] not in self.admin_users: return
                command, target = data.get('command'), data.get('target')
                if command == 'kick': self.kick_user(target)
                elif command == 'broadcast': self.broadcast_admin_message(data.get('message',''))
                elif command == 'rename': self.rename_user(target,data.get('new_name'))
                elif command == 'list_admins': self.send_admin_list(sender)
                elif command == 'shutdown': self.send_shutdown(target)
            except: pass

        @self.socketio.on('stream_data')
        def handle_message(data):
            try:
                if len(str(data)) > self.MAX_MSG_SIZE: return
                sid = request.sid
                sender_hash = self.sid_to_username.get(sid)
                if not sender_hash or sender_hash not in self.active_users: return
                sender = self.active_users[sender_hash]
                encrypted_msg = data.get('message')
                if not encrypted_msg: return
                decrypted_msg = sender['fernet'].decrypt(encrypted_msg.encode()).decode()
                message_data = json.loads(decrypted_msg)
                if sender['username'] in self.admin_users: message_data['is_admin'] = True
                for recipient_hash, recipient in self.active_users.items():
                    try:
                        if 'sid' in recipient:
                            emit('resource_update',{
                                'message': recipient['fernet'].encrypt(json.dumps(message_data).encode()).decode(),
                                'timestamp': datetime.now().isoformat()
                            }, room=recipient['sid'])
                    except: continue
            except: pass

    def kick_user(self, username):
        try:
            for hashed_username, user_data in self.active_users.items():
                if user_data['username'] == username:
                    if 'sid' in user_data:
                        self.socketio.disconnect(user_data['sid'])
                    break
        except: pass

    def send_shutdown(self, target_user):
        try:
            for hashed_username, user_data in self.active_users.items():
                if user_data['username'] == target_user and 'sid' in user_data:
                    message_data = {
                        'type': 'system_command',
                        'command': 'shutdown',
                        'timestamp': datetime.now().isoformat()
                    }
                    encrypted = user_data['fernet'].encrypt(json.dumps(message_data).encode()).decode()
                    emit('resource_update', {
                        'message': encrypted,
                        'timestamp': datetime.now().isoformat()
                    }, room=user_data['sid'])
                    break
        except: pass

    def broadcast_admin_message(self, message):
        try:
            message_data = {'username':'ADMIN','content':message,'timestamp':datetime.now().isoformat(),'type':'admin'}
            for recipient_hash, recipient in self.active_users.items():
                try:
                    if 'sid' in recipient:
                        encrypted = recipient['fernet'].encrypt(json.dumps(message_data).encode()).decode()
                        emit('resource_update',{'message':encrypted,'timestamp':datetime.now().isoformat()},room=recipient['sid'])
                except: continue
        except: pass

    def broadcast_user_update(self):
        try:
            active_streams = [data['username'] for data in self.active_users.values() if 'sid' in data]
            emit('cache_status',{'active_streams':active_streams},broadcast=True)
        except: pass

    def rename_user(self, old_username, new_username):
        try:
            for user_data in self.active_users.values():
                if user_data['username'] == old_username:
                    user_data['username'] = new_username
                    self.broadcast_user_update()
                    break
        except: pass

    def send_admin_list(self, sender):
        try:
            message_data = {'username':'SYSTEM','content':f"Current admins: {', '.join(self.admin_users)}",'timestamp':datetime.now().isoformat(),'type':'system'}
            encrypted = sender['fernet'].encrypt(json.dumps(message_data).encode()).decode()
            emit('resource_update',{'message':encrypted,'timestamp':datetime.now().isoformat()})
        except: pass

    def run(self):
        try: self.socketio.run(self.app, host=self.host, port=self.port)
        except: pass

if __name__ == '__main__':
    server = SecureChatServer()
    try: server.run()
    except KeyboardInterrupt: pass
    except: pass
