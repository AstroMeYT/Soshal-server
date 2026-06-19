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
import threading
import sqlite3
import glob

# --- Optional Cryptographic Push Library ---
try:
    from pywebpush import webpush, WebPushException
    PYWEBPUSH_AVAILABLE = True
except ImportError:
    PYWEBPUSH_AVAILABLE = False

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 8000
DB_FILE = 'soshal.db'

# Legacy paths for migration
LEGACY_USERS_FILE = 'users.json'
LEGACY_POSTS_DIR = 'posts'

# --- Cryptographic VAPID Keys for Push Notifications ---
DEFAULT_PUBLIC_VAPID_KEY = "BDrsEIWlTy1YTAZxpkN1f1C0EcuCjL15j8lxS3KaXzDE_BvlWIHEIGdmsP3hfiiG3ldbF89pWEc6foyFxSOe5es"
DEFAULT_PRIVATE_VAPID_KEY = "g00-pXj3H71-Sg_fV76D92H7K0L23-Jp81O29P8371k"
VAPID_CLAIMS = {
    "sub": "mailto:admin@yoursite.com"
}

# --- In-Memory Session Store ---
ACTIVE_SESSIONS = {}
SESSION_EXPIRY_SECONDS = 86400

# --- Validation Helpers ---
UUID_REGEX = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
MENTION_REGEX = re.compile(r'@([a-zA-Z0-9_]+)#([a-zA-Z0-9]{5})')

def is_safe_post_id(post_id):
    if not post_id or not isinstance(post_id, str):
        return False
    return bool(UUID_REGEX.match(post_id))

# --- Database & Schema Initialization ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # 1. Create users table with cryptographic key storage
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                user_id TEXT UNIQUE,
                salt TEXT,
                password_hash TEXT,
                created_at REAL,
                notification_preference TEXT DEFAULT 'following',
                push_subscription TEXT,
                public_key TEXT,
                encrypted_private_key TEXT,
                private_key_iv TEXT
            )
        ''')

        # Run dynamic column migrations for existing db files safely
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'public_key' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN public_key TEXT")
        if 'encrypted_private_key' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN encrypted_private_key TEXT")
        if 'private_key_iv' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN private_key_iv TEXT")
        
        # 2. Create follows table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS follows (
                follower TEXT,
                following TEXT,
                PRIMARY KEY (follower, following),
                FOREIGN KEY (follower) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (following) REFERENCES users(username) ON DELETE CASCADE
            )
        ''')
        
        # 3. Create posts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id TEXT PRIMARY KEY,
                author TEXT,
                content TEXT,
                image TEXT,
                timestamp REAL,
                likes INTEGER DEFAULT 0,
                FOREIGN KEY (author) REFERENCES users(username) ON DELETE CASCADE
            )
        ''')

        # 4. Create comments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id TEXT PRIMARY KEY,
                post_id TEXT,
                author TEXT,
                content TEXT,
                timestamp REAL,
                FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
                FOREIGN KEY (author) REFERENCES users(username) ON DELETE CASCADE
            )
        ''')

        # 5. Create dms table for encrypted direct messaging
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dms (
                id TEXT PRIMARY KEY,
                sender TEXT,
                receiver TEXT,
                encrypted_content TEXT,
                iv TEXT,
                timestamp REAL,
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (sender) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (receiver) REFERENCES users(username) ON DELETE CASCADE
            )
        ''')
        
        # Indexes for speed optimization
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dms_users ON dms(sender, receiver)')
        conn.commit()

    # --- Run One-Time Legacy Migration ---
    migrate_legacy_data()

def migrate_legacy_data():
    if not os.path.exists(LEGACY_USERS_FILE):
        return
    print("[*] Legacy users.json database found. Initializing safe migration...")
    try:
        with open(LEGACY_USERS_FILE, 'r') as f:
            legacy_users = json.load(f)

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            for username, udata in legacy_users.items():
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if cursor.fetchone(): continue
                cursor.execute('''
                    INSERT INTO users (username, user_id, salt, password_hash, created_at, notification_preference, push_subscription)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    username, udata.get('user_id'), udata.get('salt'), udata.get('password_hash'),
                    udata.get('created_at', time.time()), udata.get('notification_preference', 'following'),
                    json.dumps(udata.get('push_subscription')) if udata.get('push_subscription') else None
                ))

            for username, udata in legacy_users.items():
                following_list = udata.get('following', [])
                for target in following_list:
                    cursor.execute('INSERT OR IGNORE INTO follows (follower, following) VALUES (?, ?)', (username, target))
            conn.commit()
            print("[*] User accounts and social graph migrated successfully.")

            posts_migrated = 0
            if os.path.exists(LEGACY_POSTS_DIR):
                for filepath in glob.glob(os.path.join(LEGACY_POSTS_DIR, '*.json')):
                    try:
                        filename = os.path.basename(filepath)
                        name_without_ext = os.path.splitext(filename)[0]
                        if not is_safe_post_id(name_without_ext): continue
                        with open(filepath, 'r') as pf:
                            post = json.load(pf)
                        cursor.execute('SELECT 1 FROM posts WHERE id = ?', (post.get('id'),))
                        if cursor.fetchone(): continue
                        cursor.execute('''
                            INSERT INTO posts (id, author, content, image, timestamp, likes)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (post.get('id'), post.get('author'), post.get('content', ''), post.get('image'), post.get('timestamp', time.time()), post.get('likes', 0)))
                        posts_migrated += 1
                    except:
                        pass
                conn.commit()
                if posts_migrated > 0: print(f"[*] Migrated {posts_migrated} posts successfully.")

        os.rename(LEGACY_USERS_FILE, f"{LEGACY_USERS_FILE}.bak")
        if os.path.exists(LEGACY_POSTS_DIR): os.rename(LEGACY_POSTS_DIR, f"{LEGACY_POSTS_DIR}_bak")
        print("[*] Legacy migration complete. JSON files archived safely as .bak")
    except Exception as migration_error:
        print(f"[!] Migration failed: {migration_error}")


def hash_password(password, salt=None, user_id=""):
    if salt is None: salt = secrets.token_hex(16)
    combined_payload = f"{password}{user_id}".encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', combined_payload, salt.encode('utf-8'), 100000)
    return salt, key.hex()

def verify_password(stored_salt, stored_hash, provided_password, user_id=""):
    _, provided_hash = hash_password(provided_password, stored_salt, user_id)
    return secrets.compare_digest(stored_hash, provided_hash)


def dispatch_single_push(target_username, subscription, title, body, target_url="/"):
    if not PYWEBPUSH_AVAILABLE: return
    try:
        webpush(
            subscription_info=subscription,
            data=json.dumps({"title": title, "body": body, "url": target_url}),
            vapid_private_key=DEFAULT_PRIVATE_VAPID_KEY,
            vapid_claims=VAPID_CLAIMS
        )
        print(f"[Push System] Notification sent to {target_username}")
    except WebPushException as ex:
        if ex.response and ex.response.status_code in [404, 410]:
            try:
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET push_subscription = NULL WHERE username = ?', (target_username,))
                    conn.commit()
            except: pass

def process_and_send_notifications(author, content, post_id, is_comment=False, post_owner=None):
    mentions = MENTION_REGEX.findall(content)
    notified_users = set()

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # 1. Handle Mentions
        for m_username, m_userid in mentions:
            cursor.execute('SELECT username, notification_preference, push_subscription FROM users WHERE LOWER(username) = LOWER(?) AND user_id = ?', (m_username, m_userid))
            row = cursor.fetchone()
            if row:
                resolved_name, pref, sub_json = row
                if resolved_name != author and pref != 'off' and sub_json:
                    try:
                        subscription = json.loads(sub_json)
                        notified_users.add(resolved_name)
                        title = "You were mentioned in a comment!" if is_comment else "You were mentioned!"
                        dispatch_single_push(resolved_name, subscription, title, f"@{author} tagged you: \"{content[:60]}\"", f"/#post-{post_id}")
                    except: pass

        # 2. Handle Comment Notification to Post Owner
        if is_comment and post_owner and post_owner != author and post_owner not in notified_users:
            cursor.execute('SELECT notification_preference, push_subscription FROM users WHERE username = ?', (post_owner,))
            row = cursor.fetchone()
            if row:
                pref, sub_json = row
                if pref != 'off' and sub_json:
                    try:
                        subscription = json.loads(sub_json)
                        notified_users.add(post_owner)
                        dispatch_single_push(post_owner, subscription, f"New comment on your post", f"@{author} commented: \"{content[:60]}\"", f"/#post-{post_id}")
                    except: pass

        # 3. Handle Followers for New Posts
        if not is_comment:
            cursor.execute('SELECT username, notification_preference, push_subscription FROM users')
            all_users = cursor.fetchall()
            for username, pref, sub_json in all_users:
                if username == author or username in notified_users or pref == 'off' or not sub_json: continue
                should_notify = False
                if pref == 'everyone': should_notify = True
                elif pref == 'following':
                    cursor.execute('SELECT 1 FROM follows WHERE follower = ? AND following = ?', (username, author))
                    if cursor.fetchone(): should_notify = True
                if should_notify:
                    try:
                        subscription = json.loads(sub_json)
                        dispatch_single_push(username, subscription, f"New post from {author}", content[:80] if content else "Shared an image.", f"/#post-{post_id}")
                    except: pass


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
        if not auth_header or not auth_header.startswith('Bearer '): return None
        token = auth_header.split(' ')[1]
        session = ACTIVE_SESSIONS.get(token)
        if session and session['expires'] > time.time(): return session['username']
        if session: del ACTIVE_SESSIONS[token]
        return None

    def parse_post_data(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0: return {}
        try: return json.loads(self.rfile.read(content_length).decode('utf-8'))
        except: return None

    def do_POST(self):
        data = self.parse_post_data()
        if data is None: return self.send_json_response(400, {"error": "Invalid JSON"})

        # --- SIGNUP ---
        if self.path == '/api/signup':
            username, password = data.get('username'), data.get('password')
            pub_key = data.get('public_key')
            enc_priv_key = data.get('encrypted_private_key')
            priv_key_iv = data.get('private_key_iv')
            
            if not username or not password: 
                return self.send_json_response(400, {"error": "Username and password required"})
                
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM users WHERE LOWER(username) = ?', (username.lower(),))
                if cursor.fetchone(): 
                    return self.send_json_response(409, {"error": "Username already exists"})
                    
                alphabet = string.ascii_letters + string.digits
                user_id = "".join(secrets.choice(alphabet) for _ in range(5))
                salt, hashed_pwd = hash_password(password, user_id=user_id)
                
                cursor.execute('''
                    INSERT INTO users (username, user_id, salt, password_hash, created_at, notification_preference, public_key, encrypted_private_key, private_key_iv) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (username, user_id, salt, hashed_pwd, time.time(), 'following', pub_key, enc_priv_key, priv_key_iv))
                conn.commit()
            return self.send_json_response(201, {"message": "User created successfully"})

        # --- LOGIN ---
        elif self.path == '/api/login':
            username, password = data.get('username'), data.get('password')
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT salt, password_hash, user_id, public_key, encrypted_private_key, private_key_iv FROM users WHERE username = ?', (username,))
                row = cursor.fetchone()
            if not row or not verify_password(row[0], row[1], password, row[2]):
                return self.send_json_response(401, {"error": "Invalid username or password"})
            token = secrets.token_urlsafe(32)
            ACTIVE_SESSIONS[token] = {"username": username, "expires": time.time() + SESSION_EXPIRY_SECONDS}
            return self.send_json_response(200, {
                "message": "Login successful", 
                "token": token,
                "public_key": row[3],
                "encrypted_private_key": row[4],
                "private_key_iv": row[5]
            })

        # --- LOGOUT ---
        elif self.path == '/api/logout':
            auth_header = self.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                if token in ACTIVE_SESSIONS: del ACTIVE_SESSIONS[token]
            return self.send_json_response(200, {"message": "Logged out successfully"})

        # --- UPGRADE USER TO E2EE KEYS ---
        elif self.path == '/api/users/upgrade_keys':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            pub = data.get('public_key')
            priv = data.get('encrypted_private_key')
            iv = data.get('private_key_iv')
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET public_key = ?, encrypted_private_key = ?, private_key_iv = ? WHERE username = ?', (pub, priv, iv, username))
                conn.commit()
            return self.send_json_response(200, {"message": "Keys upgraded successfully"})

        # --- GET PEER PUBLIC KEY ---
        elif self.path == '/api/users/get_public_key':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            target = data.get('username')
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT public_key FROM users WHERE username = ?', (target,))
                row = cursor.fetchone()
            if not row or not row[0]: 
                return self.send_json_response(404, {"error": "Public key not found on this server."})
            return self.send_json_response(200, {"public_key": row[0]})

        # --- E2EE DIRECT MESSAGE ENDPOINTS ---
        elif self.path == '/api/dms/send':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            receiver = data.get('receiver')
            encrypted_content = data.get('encrypted_content')
            iv = data.get('iv')
            if not receiver or not encrypted_content or not iv:
                return self.send_json_response(400, {"error": "Missing messaging parameters"})
            
            dm_id, timestamp = str(uuid.uuid4()), time.time()
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO dms (id, sender, receiver, encrypted_content, iv, timestamp, is_read) VALUES (?, ?, ?, ?, ?, ?, 0)', (dm_id, username, receiver, encrypted_content, iv, timestamp))
                conn.commit()
            return self.send_json_response(201, {"message": "Secure message dispatched successfully"})

        elif self.path == '/api/dms/list':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            target_user = data.get('target_user')
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT sender, receiver, encrypted_content, iv, timestamp, is_read 
                    FROM dms 
                    WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) 
                    ORDER BY timestamp ASC
                ''', (username, target_user, target_user, username))
                rows = cursor.fetchall()
                # Automatically mark received messages as read
                cursor.execute('UPDATE dms SET is_read = 1 WHERE sender = ? AND receiver = ?', (target_user, username))
                conn.commit()
            messages = [{"sender": r[0], "receiver": r[1], "encrypted_content": r[2], "iv": r[3], "timestamp": r[4], "is_read": r[5]} for r in rows]
            return self.send_json_response(200, {"messages": messages})

        elif self.path == '/api/dms/conversations':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT DISTINCT 
                        CASE WHEN sender = ? THEN receiver ELSE sender END AS other_user
                    FROM dms
                    WHERE sender = ? OR receiver = ?
                ''', (username, username, username))
                other_users = [row[0] for row in cursor.fetchall()]
                
                conversations = []
                for other in other_users:
                    cursor.execute('''
                        SELECT encrypted_content, iv, timestamp, sender 
                        FROM dms 
                        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                        ORDER BY timestamp DESC LIMIT 1
                    ''', (username, other, other, username))
                    msg_row = cursor.fetchone()
                    
                    latest_msg = None
                    if msg_row:
                        latest_msg = {
                            "encrypted_content": msg_row[0],
                            "iv": msg_row[1],
                            "timestamp": msg_row[2],
                            "sender": msg_row[3]
                        }
                    
                    cursor.execute('''
                        SELECT COUNT(*) FROM dms 
                        WHERE sender = ? AND receiver = ? AND is_read = 0
                    ''', (other, username))
                    unread_count = cursor.fetchone()[0]
                    
                    conversations.append({
                        "other_user": other,
                        "latest_message": latest_msg,
                        "unread_count": unread_count
                    })
            return self.send_json_response(200, {"conversations": conversations})

        # --- USER PROFILE ---
        elif self.path == '/api/users/profile':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            target_user = data.get('username')
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username, user_id, notification_preference FROM users WHERE username = ?', (target_user,))
                row = cursor.fetchone()
                if not row: return self.send_json_response(404, {"error": "User not found"})
                target_username, user_id, notification_pref = row
                cursor.execute('SELECT COUNT(*) FROM follows WHERE following = ?', (target_user,))
                followers_count = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM follows WHERE follower = ?', (target_user,))
                following_count = cursor.fetchone()[0]
                cursor.execute('SELECT 1 FROM follows WHERE follower = ? AND following = ?', (username, target_user))
                is_following = bool(cursor.fetchone())
            return self.send_json_response(200, {"username": target_username, "user_id": user_id, "followers_count": followers_count, "following_count": following_count, "is_following": is_following, "is_self": target_user == username, "notification_preference": notification_pref})

        elif self.path == '/api/users/save_notifications_settings':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            preference, subscription = data.get('preference', 'following'), data.get('subscription')
            subscription_json = json.dumps(subscription) if subscription else None
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if not cursor.fetchone(): return self.send_json_response(404, {"error": "User not found"})
                if preference == 'off': cursor.execute('UPDATE users SET notification_preference = ?, push_subscription = NULL WHERE username = ?', (preference, username))
                else: cursor.execute('UPDATE users SET notification_preference = ?, push_subscription = COALESCE(?, push_subscription) WHERE username = ?', (preference, subscription_json, username))
                conn.commit()
            return self.send_json_response(200, {"message": "Settings updated", "preference": preference})

        elif self.path == '/api/users/follow':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            target_user, action = data.get('target_user'), data.get('action') 
            if target_user == username: return self.send_json_response(400, {"error": "Cannot follow yourself."})
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                if action == 'follow': cursor.execute('INSERT OR IGNORE INTO follows (follower, following) VALUES (?, ?)', (username, target_user))
                elif action == 'unfollow': cursor.execute('DELETE FROM follows WHERE follower = ? AND following = ?', (username, target_user))
                conn.commit()
            return self.send_json_response(200, {"message": f"Successfully {action}ed {target_user}"})

        # --- CREATE POST ---
        elif self.path == '/api/posts/create':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            content, image_data = data.get('content'), data.get('image')
            if not content and not image_data: return self.send_json_response(400, {"error": "Content required"})
            post_id, timestamp = str(uuid.uuid4()), time.time()
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO posts (id, author, content, image, timestamp, likes) VALUES (?, ?, ?, ?, ?, 0)', (post_id, username, content or "", image_data, timestamp))
                conn.commit()
            threading.Thread(target=process_and_send_notifications, args=(username, content or "", post_id), daemon=True).start()
            return self.send_json_response(201, {"message": "Post created", "post": {"id": post_id, "author": username, "content": content or "", "image": image_data, "timestamp": timestamp, "likes": 0, "comment_count": 0}})

        # --- SECURE DELETION ---
        elif self.path == '/api/posts/delete':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            post_id = data.get('post_id')
            if not post_id or not is_safe_post_id(post_id):
                return self.send_json_response(400, {"error": "Invalid post ID format"})
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT author FROM posts WHERE id = ?', (post_id,))
                row = cursor.fetchone()
                if not row:
                    return self.send_json_response(404, {"error": "Post not found"})
                if row[0] != username:
                    return self.send_json_response(403, {"error": "Forbidden: You do not own this post"})
                cursor.execute('DELETE FROM posts WHERE id = ?', (post_id,))
                cursor.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
                conn.commit()
            return self.send_json_response(200, {"message": "Post and associated comments successfully purged"})

        # --- COMMENTS API ---
        elif self.path == '/api/posts/comment':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            post_id, content = data.get('post_id'), data.get('content')
            if not post_id or not content: return self.send_json_response(400, {"error": "Missing data"})
            
            comment_id, timestamp = str(uuid.uuid4()), time.time()
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO comments (id, post_id, author, content, timestamp) VALUES (?, ?, ?, ?, ?)', (comment_id, post_id, username, content, timestamp))
                cursor.execute('SELECT author FROM posts WHERE id = ?', (post_id,))
                post_owner = cursor.fetchone()
                conn.commit()
            
            if post_owner:
                threading.Thread(target=process_and_send_notifications, args=(username, content, post_id, True, post_owner[0]), daemon=True).start()
            return self.send_json_response(201, {"comment": {"id": comment_id, "author": username, "content": content, "timestamp": timestamp}})

        elif self.path == '/api/posts/comments':
            post_id = data.get('post_id')
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, author, content, timestamp FROM comments WHERE post_id = ? ORDER BY timestamp ASC', (post_id,))
                rows = cursor.fetchall()
            comments = [{"id": r[0], "author": r[1], "content": r[2], "timestamp": r[3]} for r in rows]
            return self.send_json_response(200, {"comments": comments})

        # --- LIST POSTS ---
        elif self.path == '/api/posts/list':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            limit, feed_type = data.get('limit', 10), data.get('feed_type', 'global') 
            
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM follows WHERE follower = ?', (username,))
                is_following_empty = (cursor.fetchone()[0] == 0)
                all_posts = []

                if feed_type == 'following' and not is_following_empty:
                    cursor.execute('''
                        SELECT p.id, p.author, p.content, p.image, p.timestamp, p.likes, (SELECT COUNT(*) FROM comments WHERE post_id = p.id)
                        FROM posts p JOIN follows f ON p.author = f.following
                        WHERE f.follower = ? ORDER BY p.timestamp DESC LIMIT ?
                    ''', (username, limit))
                    all_posts = cursor.fetchall()
                elif feed_type == 'global':
                    cursor.execute('SELECT id, author, content, image, timestamp, likes, (SELECT COUNT(*) FROM comments WHERE post_id = posts.id) FROM posts ORDER BY timestamp DESC LIMIT ?', (limit,))
                    all_posts = cursor.fetchall()

            return self.send_json_response(200, {
                "posts": [{"id": r[0], "author": r[1], "content": r[2], "image": r[3], "timestamp": r[4], "likes": r[5], "comment_count": r[6]} for r in all_posts],
                "is_following_empty": is_following_empty
            })

        # --- USER SPECIFIC POSTS ---
        elif self.path == '/api/posts/user':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            target_user, limit = data.get('username'), data.get('limit', 50)
            
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, author, content, image, timestamp, likes, (SELECT COUNT(*) FROM comments WHERE post_id = posts.id) FROM posts WHERE author = ? ORDER BY timestamp DESC LIMIT ?', (target_user, limit))
                rows = cursor.fetchall()
            return self.send_json_response(200, {"posts": [{"id": r[0], "author": r[1], "content": r[2], "image": r[3], "timestamp": r[4], "likes": r[5], "comment_count": r[6]} for r in rows]})

        # --- LIKE POST ---
        elif self.path == '/api/posts/like':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            post_id, action = data.get('post_id'), data.get('action', 'like')
            if not is_safe_post_id(post_id): return self.send_json_response(400, {"error": "Invalid format"})
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                if action == 'like': cursor.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', (post_id,))
                elif action == 'unlike': cursor.execute('UPDATE posts SET likes = CASE WHEN likes > 0 THEN likes - 1 ELSE 0 END WHERE id = ?', (post_id,))
                conn.commit()
                cursor.execute('SELECT likes FROM posts WHERE id = ?', (post_id,))
                row = cursor.fetchone()
            return self.send_json_response(200, {"message": "Like updated", "likes": row[0] if row else 0})

        # --- SEARCH ---
        elif self.path == '/api/search':
            username = self.get_authenticated_user()
            if not username: return self.send_json_response(401, {"error": "Unauthorized."})
            query, search_type = data.get('query', '').strip().lower(), data.get('type', 'posts')
            if not query: return self.send_json_response(200, {"results": []})
            results = []

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                if search_type == 'users':
                    cursor.execute('SELECT username, user_id FROM users WHERE LOWER(username) LIKE ? OR LOWER(username) = ? OR LOWER(user_id) = ?', (f"%{query}%", query, query.replace('#', '')))
                    for row in cursor.fetchall():
                        uname, uid = row
                        cursor.execute('SELECT COUNT(*) FROM follows WHERE following = ?', (uname,))
                        followers = cursor.fetchone()[0]
                        cursor.execute('SELECT COUNT(*) FROM follows WHERE follower = ?', (uname,))
                        following = cursor.fetchone()[0]
                        results.append({"username": uname, "user_id": uid or '00000', "followers_count": followers, "following_count": following})
                else:
                    cursor.execute('''
                        SELECT id, author, content, image, timestamp, likes, (SELECT COUNT(*) FROM comments WHERE post_id = posts.id) 
                        FROM posts WHERE LOWER(content) LIKE ? OR LOWER(author) LIKE ? ORDER BY timestamp DESC
                    ''', (f"%{query}%", f"%{query}%"))
                    for r in cursor.fetchall():
                        results.append({"id": r[0], "author": r[1], "content": r[2], "image": r[3], "timestamp": r[4], "likes": r[5], "comment_count": r[6]})
            return self.send_json_response(200, {"results": results})
        else:
            return self.send_json_response(404, {"error": "Endpoint not found"})

class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    init_db()
    if not PYWEBPUSH_AVAILABLE: print("[!] Run: 'pip install pywebpush' to enable background cryptographic pushes.")
    with ReusableThreadingTCPServer((HOST, PORT), SoshalRequestHandler) as httpd:
        print(f"[*] Threaded SQLite-backed Soshal API Server running at http://{HOST}:{PORT}")
        try: httpd.serve_forever()
        except KeyboardInterrupt: print("\n[*] Server stopped.")