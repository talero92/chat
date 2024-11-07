from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import os, hashlib
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import socket

class SecureChatServer:
    def __init__(self, port=5000):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = os.urandom(24)
    
    self.fernet_key = base64.urlsafe_b64encode(os.urandom(32))
    self.encryption_key = self.fernet_key.decode()
    self.fernet = Fernet(self.fernet_key)
    
    self.socketio = SocketIO(self.app, path='/api/resources/fetch', logger=False, engineio_logger=False, cors_allowed_origins="*")
    
    @self.app.after_request
    def after_request(response):
        [response.headers.add(k, v) for k, v in {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS'
        }.items()]
        return response
    
    # Simple IP detection
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        self.host = s.getsockname()[0]
    except:
        self.host = '127.0.0.1'
    finally:
        s.close()
    
    self.port = port
    self.active_users = {}
    self.sid_to_username = {}
    
    self.setup_routes()
    self.setup_socketio()
    
    self.MAX_MSG_SIZE = 1024 * 1024

    def hash_username(self, username): return hashlib.sha256(username.encode()).hexdigest()

    def setup_routes(self):
        @self.app.route('/assets/data/stream', methods=['GET'])
        def health_check(): return jsonify({'status': 'ok', 'cache-status': 'hit'})

        @self.app.route('/api/resources/validate', methods=['POST', 'OPTIONS'])
        def authenticate():
            if request.method == 'OPTIONS': return jsonify({'status': 'ok'})
            try:
                username = str(request.get_json(force=True).get('username', ''))
                if not username: return jsonify({'error': 'Invalid identifier'}), 400
                hashed_username = self.hash_username(username)
                if hashed_username in self.active_users: return jsonify({'error': 'Identifier in use'}), 400
                self.active_users[hashed_username] = {'connected_at': datetime.now().isoformat(), 'address': request.remote_addr, 'username': username}
                return jsonify({'status': 'ok', 'encryption_key': self.encryption_key})
            except Exception as e: print(f"Auth error: {str(e)}"); return jsonify({'error': str(e)}), 500

    def setup_socketio(self):
        @self.socketio.on('connect')
        def handle_connect(): pass

        @self.socketio.on('register')
        def handle_register(data):
            try:
                if (username := data.get('username')) and (hashed_username := self.hash_username(username)) in self.active_users:
                    self.sid_to_username[request.sid] = hashed_username; self.active_users[hashed_username]['sid'] = request.sid; self.broadcast_user_update()
            except Exception as e: print(f"Registration error: {str(e)}")

        @self.socketio.on('disconnect')
        def handle_disconnect():
            if (sid := request.sid) in self.sid_to_username and (hashed_username := self.sid_to_username[sid]) in self.active_users:
                del self.active_users[hashed_username], self.sid_to_username[sid]; self.broadcast_user_update()

        @self.socketio.on('stream_data')
        def handle_message(data):
            try:
                if len(str(data)) > self.MAX_MSG_SIZE:
                    return

                # Keep original event name for compatibility
                emit('resource_update', data, broadcast=True)
            except Exception:
                pass

    def broadcast_user_update(self): emit('cache_status', {'active_streams': [data['username'] for data in self.active_users.values()]}, broadcast=True)

    def run(self):
        try:
            print(f"Starting server on {self.host}:{self.port}")
            print(f"For remote connections, use: {self.host}:{self.port}")
            self.socketio.run(self.app, host=self.host, port=self.port, allow_unsafe_werkzeug=True)
        except Exception as e:
            print(f"Server error: {e}")

if __name__ == '__main__':
    server = SecureChatServer()
    try: server.run()
    except KeyboardInterrupt: print("\nServer shutting down...")