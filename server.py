import http.server
import socketserver
import json
import os
import hashlib
import secrets
import time
import uuid
import string
import re

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 8000
POSTS_DIR = 'posts'
USERS_FILE = 'users.json'

# --- In-Memory Session Store ---
ACTIVE_SESSIONS = {}
SESSION_EXPIRY_SECONDS = 86400 # 24 hours

# --- Validation Helpers ---
UUID_REGEX = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)

def is_safe_post_id(post_id):
    """Strictly validates that the post_id matches a standard UUID v4 format."""
    if not post_id or not isinstance(post_id, str):
        return False
    return bool(UUID_REGEX.match(post_id))

# --- Initialization ---
def setup_filesystem():
    """Ensure the necessary folders and files exist."""
    if not os.path.exists(POSTS_DIR):
        os.makedirs(POSTS_DIR)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)

setup_filesystem()

# --- Database Helpers ---
def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

# --- Security Helpers ---
def hash_password(password, salt=None, user_id=""):
    """Hashes a password using PBKDF2 HMAC and SHA-256 with the unique user_id injected."""
    if salt is None:
        salt = secrets.token_hex(16)
    
    combined_payload = f"{password}{user_id}".encode('utf-8')
    
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        combined_payload, 
        salt.encode('utf-8'), 
        100000
    )
    return salt, key.hex()

def verify_password(stored_salt, stored_hash, provided_password, user_id=""):
    """Verifies a provided password against the stored salt, hash, and user_id payload."""
    _, provided_hash = hash_password(provided_password, stored_salt, user_id)
    return secrets.compare_digest(stored_hash, provided_hash)

# --- Request Handler ---
class SoshalRequestHandler(http.server.BaseHTTPRequestHandler):

    def send_json_response(self, status_code, payload):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.end_headers()

    def get_authenticated_user(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header.split(' ')[1]
        session = ACTIVE_SESSIONS.get(token)
        
        if session and session['expires'] > time.time():
            return session['username']
        
        if session:
            del ACTIVE_SESSIONS[token]
        return None

    def parse_post_data(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        post_data = self.rfile.read(content_length)
        try:
            return json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            return None

    def do_POST(self):
        data = self.parse_post_data()
        if data is None:
            return self.send_json_response(400, {"error": "Invalid JSON format"})

        # --- 1. SIGNUP ---
        if self.path == '/api/signup':
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return self.send_json_response(400, {"error": "Username and password required"})

            users = load_users()
            
            # Strict Case-Insensitive Username Check
            username_lower = username.lower()
            if any(u.lower() == username_lower for u in users):
                return self.send_json_response(409, {"error": "Username already exists"})

            # Generate unique 5-character User ID (aA0-zZ9)
            alphabet = string.ascii_letters + string.digits
            user_id = "".join(secrets.choice(alphabet) for _ in range(5))

            # Apply the user_id to the hashed key payload
            salt, hashed_pwd = hash_password(password, user_id=user_id)
            
            users[username] = {
                "user_id": user_id,
                "salt": salt,
                "password_hash": hashed_pwd,
                "created_at": time.time(),
                "followers": [],
                "following": []
            }
            save_users(users)
            return self.send_json_response(201, {"message": "User created successfully"})

        # --- 2. LOGIN ---
        elif self.path == '/api/login':
            username = data.get('username')
            password = data.get('password')

            users = load_users()
            user = users.get(username)

            if not user:
                return self.send_json_response(401, {"error": "Invalid username or password"})
            
            user_id = user.get('user_id', '') 
            if not verify_password(user['salt'], user['password_hash'], password, user_id):
                return self.send_json_response(401, {"error": "Invalid username or password"})

            token = secrets.token_urlsafe(32)
            ACTIVE_SESSIONS[token] = {
                "username": username,
                "expires": time.time() + SESSION_EXPIRY_SECONDS
            }

            return self.send_json_response(200, {
                "message": "Login successful",
                "token": token
            })

        # --- 3. LOGOUT ---
        elif self.path == '/api/logout':
            auth_header = self.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                if token in ACTIVE_SESSIONS:
                    del ACTIVE_SESSIONS[token]
            return self.send_json_response(200, {"message": "Logged out successfully"})

        # --- USER PROFILE ---
        elif self.path == '/api/users/profile':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})
            
            target_user = data.get('username')
            if not target_user:
                return self.send_json_response(400, {"error": "Target username required"})

            users = load_users()
            if target_user not in users:
                return self.send_json_response(404, {"error": "User not found"})

            target = users[target_user]
            followers = target.get('followers', [])
            following = target.get('following', [])

            return self.send_json_response(200, {
                "username": target_user,
                "user_id": target.get('user_id', 'N/A'),
                "followers_count": len(followers),
                "following_count": len(following),
                "is_following": username in followers,
                "is_self": target_user == username 
            })

        # --- FOLLOW/UNFOLLOW ---
        elif self.path == '/api/users/follow':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})
            
            target_user = data.get('target_user')
            action = data.get('action') 

            if not target_user:
                return self.send_json_response(400, {"error": "Target user is required."})
            if target_user == username:
                return self.send_json_response(400, {"error": "You cannot follow yourself."})

            users = load_users()
            
            if username not in users:
                return self.send_json_response(401, {"error": "User session invalid."})
            if target_user not in users:
                return self.send_json_response(404, {"error": "User not found"})

            if 'following' not in users[username]: users[username]['following'] = []
            if 'followers' not in users[username]: users[username]['followers'] = []
            if 'following' not in users[target_user]: users[target_user]['following'] = []
            if 'followers' not in users[target_user]: users[target_user]['followers'] = []

            if action == 'follow':
                if target_user not in users[username]['following']:
                    users[username]['following'].append(target_user)
                if username not in users[target_user]['followers']:
                    users[target_user]['followers'].append(username)
            elif action == 'unfollow':
                if target_user in users[username]['following']:
                    users[username]['following'].remove(target_user)
                if username in users[target_user]['followers']:
                    users[target_user]['followers'].remove(username)

            save_users(users)
            return self.send_json_response(200, {"message": f"Successfully {action}ed {target_user}"})

        # --- 4. CREATE POST ---
        elif self.path == '/api/posts/create':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            content = data.get('content')
            image_data = data.get('image')
            
            if not content and not image_data:
                return self.send_json_response(400, {"error": "Post content or image required"})

            post_id = str(uuid.uuid4())
            post_data = {
                "id": post_id,
                "author": username,
                "content": content or "",
                "image": image_data,
                "timestamp": time.time(),
                "likes": 0
            }

            file_path = os.path.join(POSTS_DIR, f"{post_id}.json")
            with open(file_path, 'w') as f:
                json.dump(post_data, f, indent=4)

            return self.send_json_response(201, {"message": "Post created", "post": post_data})

        # --- 5. LIST POSTS (Global & Friends) ---
        elif self.path == '/api/posts/list':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            limit = data.get('limit', 10)
            feed_type = data.get('feed_type', 'global') 
            
            users = load_users()
            current_user_data = users.get(username, {})
            following_list = current_user_data.get('following', [])
            
            is_following_empty = (len(following_list) == 0)

            all_posts = []
            
            if feed_type == 'following' and is_following_empty:
                pass 
            else:
                for filename in os.listdir(POSTS_DIR):
                    if filename.endswith('.json'):
                        # Defensive check: Ensure we only parse files matching valid UUID names
                        name_without_ext = os.path.splitext(filename)[0]
                        if not is_safe_post_id(name_without_ext):
                            continue
                        with open(os.path.join(POSTS_DIR, filename), 'r') as f:
                            post = json.load(f)
                            if feed_type == 'following':
                                if post['author'] in following_list:
                                    all_posts.append(post)
                            else:
                                all_posts.append(post)

                all_posts.sort(key=lambda x: x['timestamp'], reverse=True)
                
            return self.send_json_response(200, {
                "posts": all_posts[:limit],
                "is_following_empty": is_following_empty
            })

        # --- 6. USER SPECIFIC POSTS (Profile Page) ---
        elif self.path == '/api/posts/user':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})
            
            target_user = data.get('username')
            if not target_user:
                return self.send_json_response(400, {"error": "Target username required"})

            limit = data.get('limit', 50)
            
            all_posts = []
            for filename in os.listdir(POSTS_DIR):
                if filename.endswith('.json'):
                    name_without_ext = os.path.splitext(filename)[0]
                    if not is_safe_post_id(name_without_ext):
                        continue
                    with open(os.path.join(POSTS_DIR, filename), 'r') as f:
                        post = json.load(f)
                        if post['author'] == target_user:
                            all_posts.append(post)

            all_posts.sort(key=lambda x: x['timestamp'], reverse=True)
            return self.send_json_response(200, {"posts": all_posts[:limit]})

        # --- 7. LIKE POST ---
        elif self.path == '/api/posts/like':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            post_id = data.get('post_id')
            action = data.get('action', 'like')
            
            # Defensive validation: Ensure post_id exists and conforms to a clean UUID
            if not post_id or not is_safe_post_id(post_id):
                return self.send_json_response(400, {"error": "Invalid post ID format"})

            # Enforce clean filename sanitization using basename
            sanitized_id = os.path.basename(post_id)
            file_path = os.path.join(POSTS_DIR, f"{sanitized_id}.json")
            
            if not os.path.exists(file_path):
                return self.send_json_response(404, {"error": "Post not found"})

            with open(file_path, 'r') as f:
                post_data = json.load(f)

            if action == 'like':
                post_data['likes'] = post_data.get('likes', 0) + 1
            elif action == 'unlike':
                post_data['likes'] = max(0, post_data.get('likes', 0) - 1)

            with open(file_path, 'w') as f:
                json.dump(post_data, f, indent=4)

            return self.send_json_response(200, {"message": "Like updated", "likes": post_data['likes']})

        # --- 8. SEARCH ---
        elif self.path == '/api/search':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            query = data.get('query', '').strip().lower()
            search_type = data.get('type', 'posts')

            if not query:
                return self.send_json_response(200, {"results": []})

            results = []

            if search_type == 'users':
                users = load_users()
                for uname, udata in users.items():
                    user_id = udata.get('user_id', '').lower()
                    if query in uname.lower() or query == f"@{uname.lower()}" or query == user_id or query == f"#{user_id}":
                        results.append({
                            "username": uname,
                            "user_id": udata.get('user_id', '00000'),
                            "followers_count": len(udata.get('followers', [])),
                            "following_count": len(udata.get('following', []))
                        })
            else:
                for filename in os.listdir(POSTS_DIR):
                    if filename.endswith('.json'):
                        name_without_ext = os.path.splitext(filename)[0]
                        if not is_safe_post_id(name_without_ext):
                            continue
                        with open(os.path.join(POSTS_DIR, filename), 'r') as f:
                            post = json.load(f)
                            if query in post.get('content', '').lower() or query in post.get('author', '').lower():
                                results.append(post)
                results.sort(key=lambda x: x['timestamp'], reverse=True)

            return self.send_json_response(200, {"results": results})

        else:
            return self.send_json_response(404, {"error": "Endpoint not found"})

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    with ReusableTCPServer((HOST, PORT), SoshalRequestHandler) as httpd:
        print(f"[*] Soshal API Server running at http://{HOST}:{PORT}")
        print("[*] Waiting for requests...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")
            httpd.server_close()