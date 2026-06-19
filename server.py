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
# Mathematically valid Elliptic Curve P-256 Keys matching the client VAPID configuration
DEFAULT_PUBLIC_VAPID_KEY = "BDrsEIWlTy1YTAZxpkN1f1C0EcuCjL15j8lxS3KaXzDE_BvlWIHEIGdmsP3hfiiG3ldbF89pWEc6foyFxSOe5es"
DEFAULT_PRIVATE_VAPID_KEY = "g00-pXj3H71-Sg_fV76D92H7K0L23-Jp81O29P8371k" # Private point matching the above public key
VAPID_CLAIMS = {
    "sub": "mailto:admin@yoursite.com"
}

# --- In-Memory Session Store (Fast RAM Lookup) ---
ACTIVE_SESSIONS = {}
SESSION_EXPIRY_SECONDS = 86400  # 24 hours

# --- Validation Helpers ---
UUID_REGEX = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
MENTION_REGEX = re.compile(r'@([a-zA-Z0-9_]+)#([a-zA-Z0-9]{5})')

def is_safe_post_id(post_id):
    """Strictly validates that the post_id matches a standard UUID v4 format."""
    if not post_id or not isinstance(post_id, str):
        return False
    return bool(UUID_REGEX.match(post_id))

# --- Database & Schema Initialization ---
def init_db():
    """Initializes the database schema and performs legacy JSON database migration if present."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # 1. Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                user_id TEXT UNIQUE,
                salt TEXT,
                password_hash TEXT,
                created_at REAL,
                notification_preference TEXT DEFAULT 'following',
                push_subscription TEXT
            )
        ''')
        
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
        
        # Create indexing paths for speed optimization
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_timestamp ON posts(timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following)')
        conn.commit()

    # --- Run One-Time Legacy Migration ---
    migrate_legacy_data()

def migrate_legacy_data():
    """Reads legacy flat JSON files and migrates them safely into SQLite tables."""
    if not os.path.exists(LEGACY_USERS_FILE):
        return

    print("[*] Legacy users.json database found. Initializing safe migration...")
    try:
        with open(LEGACY_USERS_FILE, 'r') as f:
            legacy_users = json.load(f)

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Migrate Users
            for username, udata in legacy_users.items():
                # Check if user already exists in db to avoid duplicate conflicts
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if cursor.fetchone():
                    continue

                # Insert user profile
                cursor.execute('''
                    INSERT INTO users (username, user_id, salt, password_hash, created_at, notification_preference, push_subscription)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    username,
                    udata.get('user_id'),
                    udata.get('salt'),
                    udata.get('password_hash'),
                    udata.get('created_at', time.time()),
                    udata.get('notification_preference', 'following'),
                    json.dumps(udata.get('push_subscription')) if udata.get('push_subscription') else None
                ))

            # Migrate Follower network graph
            for username, udata in legacy_users.items():
                following_list = udata.get('following', [])
                for target in following_list:
                    cursor.execute('INSERT OR IGNORE INTO follows (follower, following) VALUES (?, ?)', (username, target))
            
            conn.commit()
            print("[*] User accounts and social graph migrated successfully.")

            # Migrate Posts
            posts_migrated = 0
            if os.path.exists(LEGACY_POSTS_DIR):
                for filepath in glob.glob(os.path.join(LEGACY_POSTS_DIR, '*.json')):
                    try:
                        filename = os.path.basename(filepath)
                        name_without_ext = os.path.splitext(filename)[0]
                        if not is_safe_post_id(name_without_ext):
                            continue

                        with open(filepath, 'r') as pf:
                            post = json.load(pf)

                        cursor.execute('SELECT 1 FROM posts WHERE id = ?', (post.get('id'),))
                        if cursor.fetchone():
                            continue

                        cursor.execute('''
                            INSERT INTO posts (id, author, content, image, timestamp, likes)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            post.get('id'),
                            post.get('author'),
                            post.get('content', ''),
                            post.get('image'),
                            post.get('timestamp', time.time()),
                            post.get('likes', 0)
                        ))
                        posts_migrated += 1
                    except Exception as post_err:
                        print(f"[!] Warning migrating post file {filepath}: {post_err}")
                
                conn.commit()
                if posts_migrated > 0:
                    print(f"[*] Migrated {posts_migrated} posts successfully.")

        # Safely archive the old JSON files to avoid repetitive scanning
        os.rename(LEGACY_USERS_FILE, f"{LEGACY_USERS_FILE}.bak")
        if os.path.exists(LEGACY_POSTS_DIR):
            os.rename(LEGACY_POSTS_DIR, f"{LEGACY_POSTS_DIR}_bak")
        print("[*] Legacy migration complete. JSON files archived safely as .bak")

    except Exception as migration_error:
        print(f"[!] Migration failed: {migration_error}")


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


# --- Push Notification Engine ---
def dispatch_single_push(target_username, subscription, title, body, target_url="/"):
    """Delivers a cryptographic standard push event to a target user's browser."""
    if not PYWEBPUSH_AVAILABLE:
        print(f"[Push Warning] Cannot notify {target_username}. Run 'pip install pywebpush' on the server.")
        return

    try:
        webpush(
            subscription_info=subscription,
            data=json.dumps({"title": title, "body": body, "url": target_url}),
            vapid_private_key=DEFAULT_PRIVATE_VAPID_KEY,
            vapid_claims=VAPID_CLAIMS
        )
        print(f"[Push System] Notification sent to {target_username}")
    except WebPushException as ex:
        print(f"[Push Error] WebPush failed for {target_username}: {ex}")
        # Automatically clean up expired or invalid subscriptions
        if ex.response and ex.response.status_code in [404, 410]:
            try:
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET push_subscription = NULL WHERE username = ?', (target_username,))
                    conn.commit()
                print(f"[Push System] Cleared expired subscription for {target_username}")
            except Exception as clean_err:
                print(f"[Push Error] Failed to clear subscription: {clean_err}")

def process_and_send_notifications(author, content, post_id):
    """Parses mentions and social graph connections to dispatch push notifications in the background."""
    # Find explicit mentions: @Username#userid
    mentions = MENTION_REGEX.findall(content)
    notified_users = set()

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # 1. Handle Mentions
        for m_username, m_userid in mentions:
            cursor.execute('''
                SELECT username, notification_preference, push_subscription 
                FROM users 
                WHERE LOWER(username) = LOWER(?) AND user_id = ?
            ''', (m_username, m_userid))
            row = cursor.fetchone()
            if row:
                resolved_name, pref, sub_json = row
                if resolved_name != author and pref != 'off' and sub_json:
                    try:
                        subscription = json.loads(sub_json)
                        notified_users.add(resolved_name)
                        dispatch_single_push(
                            target_username=resolved_name,
                            subscription=subscription,
                            title="You were mentioned!",
                            body=f"@{author} tagged you: \"{content[:60]}\"",
                            target_url=f"/#post-{post_id}"
                        )
                    except Exception as parse_err:
                        print(f"[Push Error] Failed to parse subscription payload for {resolved_name}: {parse_err}")

        # 2. Handle Followers & System Notifications
        cursor.execute('SELECT username, notification_preference, push_subscription FROM users')
        all_users = cursor.fetchall()
        
        for username, pref, sub_json in all_users:
            if username == author or username in notified_users or pref == 'off' or not sub_json:
                continue
                
            should_notify = False
            if pref == 'everyone':
                should_notify = True
            elif pref == 'following':
                # Check if this user is a follower of the author
                cursor.execute('SELECT 1 FROM follows WHERE follower = ? AND following = ?', (username, author))
                if cursor.fetchone():
                    should_notify = True
                    
            if should_notify:
                try:
                    subscription = json.loads(sub_json)
                    dispatch_single_push(
                        target_username=username,
                        subscription=subscription,
                        title=f"New post from {author}",
                        body=content[:80] if content else "Shared an image.",
                        target_url=f"/#post-{post_id}"
                    )
                except Exception as parse_err:
                    print(f"[Push Error] Failed to parse subscription payload for {username}: {parse_err}")


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

            # Strict Case-Insensitive Username Check
            username_lower = username.lower()
            
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM users WHERE LOWER(username) = ?', (username_lower,))
                if cursor.fetchone():
                    return self.send_json_response(409, {"error": "Username already exists"})

                # Generate unique 5-character User ID (aA0-zZ9)
                alphabet = string.ascii_letters + string.digits
                user_id = "".join(secrets.choice(alphabet) for _ in range(5))

                salt, hashed_pwd = hash_password(password, user_id=user_id)
                
                cursor.execute('''
                    INSERT INTO users (username, user_id, salt, password_hash, created_at, notification_preference)
                    VALUES (?, ?, ?, ?, ?, 'following')
                ''', (username, user_id, salt, hashed_pwd, time.time()))
                conn.commit()

            return self.send_json_response(201, {"message": "User created successfully"})

        # --- 2. LOGIN ---
        elif self.path == '/api/login':
            username = data.get('username')
            password = data.get('password')

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT salt, password_hash, user_id FROM users WHERE username = ?', (username,))
                row = cursor.fetchone()

            if not row:
                return self.send_json_response(401, {"error": "Invalid username or password"})
            
            salt, stored_hash, user_id = row
            if not verify_password(salt, stored_hash, password, user_id):
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

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT username, user_id, notification_preference 
                    FROM users WHERE username = ?
                ''', (target_user,))
                row = cursor.fetchone()
                
                if not row:
                    return self.send_json_response(404, {"error": "User not found"})
                
                target_username, user_id, notification_pref = row
                
                # Fetch statistics through aggregated indexes
                cursor.execute('SELECT COUNT(*) FROM follows WHERE following = ?', (target_user,))
                followers_count = cursor.fetchone()[0]

                cursor.execute('SELECT COUNT(*) FROM follows WHERE follower = ?', (target_user,))
                following_count = cursor.fetchone()[0]

                cursor.execute('SELECT 1 FROM follows WHERE follower = ? AND following = ?', (username, target_user))
                is_following = bool(cursor.fetchone())

            return self.send_json_response(200, {
                "username": target_username,
                "user_id": user_id or 'N/A',
                "followers_count": followers_count,
                "following_count": following_count,
                "is_following": is_following,
                "is_self": target_user == username,
                "notification_preference": notification_pref
            })

        # --- SAVE NOTIFICATION PREFERENCES & SUBSCRIPTION ---
        elif self.path == '/api/users/save_notifications_settings':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            preference = data.get('preference', 'following')
            subscription = data.get('subscription')

            if preference not in ['off', 'following', 'everyone']:
                return self.send_json_response(400, {"error": "Invalid preference option"})

            subscription_json = json.dumps(subscription) if subscription else None

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if not cursor.fetchone():
                    return self.send_json_response(404, {"error": "User profile not found"})

                if preference == 'off':
                    cursor.execute('''
                        UPDATE users 
                        SET notification_preference = ?, push_subscription = NULL 
                        WHERE username = ?
                    ''', (preference, username))
                else:
                    cursor.execute('''
                        UPDATE users 
                        SET notification_preference = ?, push_subscription = COALESCE(?, push_subscription) 
                        WHERE username = ?
                    ''', (preference, subscription_json, username))
                conn.commit()

            return self.send_json_response(200, {
                "message": "Notification preferences updated successfully",
                "preference": preference
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

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                
                # Check validity of both parties
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if not cursor.fetchone():
                    return self.send_json_response(401, {"error": "User session invalid."})

                cursor.execute('SELECT 1 FROM users WHERE username = ?', (target_user,))
                if not cursor.fetchone():
                    return self.send_json_response(404, {"error": "User not found"})

                if action == 'follow':
                    cursor.execute('INSERT OR IGNORE INTO follows (follower, following) VALUES (?, ?)', (username, target_user))
                elif action == 'unfollow':
                    cursor.execute('DELETE FROM follows WHERE follower = ? AND following = ?', (username, target_user))
                conn.commit()

            return self.send_json_response(200, {"message": f"Successfully {action}ed {target_user}"})

        # --- CREATE POST ---
        elif self.path == '/api/posts/create':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            content = data.get('content')
            image_data = data.get('image')
            
            if not content and not image_data:
                return self.send_json_response(400, {"error": "Post content or image required"})

            post_id = str(uuid.uuid4())
            timestamp = time.time()

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO posts (id, author, content, image, timestamp, likes)
                    VALUES (?, ?, ?, ?, ?, 0)
                ''', (post_id, username, content or "", image_data, timestamp))
                conn.commit()

            post_data = {
                "id": post_id,
                "author": username,
                "content": content or "",
                "image": image_data,
                "timestamp": timestamp,
                "likes": 0
            }

            # Dispatch background non-blocking Web Push routines
            threading.Thread(
                target=process_and_send_notifications,
                args=(username, content or "", post_id),
                daemon=True
            ).start()

            return self.send_json_response(201, {"message": "Post created", "post": post_data})

        # --- LIST POSTS ---
        elif self.path == '/api/posts/list':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            limit = data.get('limit', 10)
            feed_type = data.get('feed_type', 'global') 
            
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                
                # Check if following graph is empty
                cursor.execute('SELECT COUNT(*) FROM follows WHERE follower = ?', (username,))
                following_count = cursor.fetchone()[0]
                is_following_empty = (following_count == 0)

                all_posts = []

                if feed_type == 'following':
                    if not is_following_empty:
                        cursor.execute('''
                            SELECT p.id, p.author, p.content, p.image, p.timestamp, p.likes 
                            FROM posts p
                            JOIN follows f ON p.author = f.following
                            WHERE f.follower = ?
                            ORDER BY p.timestamp DESC
                            LIMIT ?
                        ''', (username, limit))
                        all_posts = cursor.fetchall()
                else:
                    cursor.execute('''
                        SELECT id, author, content, image, timestamp, likes 
                        FROM posts 
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (limit,))
                    all_posts = cursor.fetchall()

            posts_list = []
            for row in all_posts:
                posts_list.append({
                    "id": row[0],
                    "author": row[1],
                    "content": row[2],
                    "image": row[3],
                    "timestamp": row[4],
                    "likes": row[5]
                })

            return self.send_json_response(200, {
                "posts": posts_list,
                "is_following_empty": is_following_empty
            })

        # --- USER SPECIFIC POSTS ---
        elif self.path == '/api/posts/user':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})
            
            target_user = data.get('username')
            if not target_user:
                return self.send_json_response(400, {"error": "Target username required"})

            limit = data.get('limit', 50)
            
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, author, content, image, timestamp, likes 
                    FROM posts 
                    WHERE author = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (target_user, limit))
                rows = cursor.fetchall()

            posts_list = []
            for row in rows:
                posts_list.append({
                    "id": row[0],
                    "author": row[1],
                    "content": row[2],
                    "image": row[3],
                    "timestamp": row[4],
                    "likes": row[5]
                })

            return self.send_json_response(200, {"posts": posts_list})

        # --- LIKE POST ---
        elif self.path == '/api/posts/like':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            post_id = data.get('post_id')
            action = data.get('action', 'like')
            
            if not post_id or not is_safe_post_id(post_id):
                return self.send_json_response(400, {"error": "Invalid post ID format"})

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM posts WHERE id = ?', (post_id,))
                if not cursor.fetchone():
                    return self.send_json_response(404, {"error": "Post not found"})

                if action == 'like':
                    cursor.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', (post_id,))
                elif action == 'unlike':
                    cursor.execute('UPDATE posts SET likes = MAX(0, likes - 1) WHERE id = ?', (post_id,))
                conn.commit()

                cursor.execute('SELECT likes FROM posts WHERE id = ?', (post_id,))
                likes = cursor.fetchone()[0]

            return self.send_json_response(200, {"message": "Like updated", "likes": likes})

        # --- SEARCH ---
        elif self.path == '/api/search':
            username = self.get_authenticated_user()
            if not username:
                return self.send_json_response(401, {"error": "Unauthorized."})

            query = data.get('query', '').strip().lower()
            search_type = data.get('type', 'posts')

            if not query:
                return self.send_json_response(200, {"results": []})

            results = []

            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()

                if search_type == 'users':
                    # Search matching username or suffix
                    cursor.execute('''
                        SELECT username, user_id FROM users 
                        WHERE LOWER(username) LIKE ? 
                           OR LOWER(username) = ? 
                           OR LOWER(user_id) = ?
                    ''', (f"%{query}%", query, query.replace('#', '')))
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        uname, uid = row
                        
                        # Followers stats lookup
                        cursor.execute('SELECT COUNT(*) FROM follows WHERE following = ?', (uname,))
                        followers = cursor.fetchone()[0]

                        cursor.execute('SELECT COUNT(*) FROM follows WHERE follower = ?', (uname,))
                        following = cursor.fetchone()[0]

                        results.append({
                            "username": uname,
                            "user_id": uid or '00000',
                            "followers_count": followers,
                            "following_count": following
                        })
                else:
                    # Content/author matching search
                    cursor.execute('''
                        SELECT id, author, content, image, timestamp, likes 
                        FROM posts 
                        WHERE LOWER(content) LIKE ? OR LOWER(author) LIKE ?
                        ORDER BY timestamp DESC
                    ''', (f"%{query}%", f"%{query}%"))
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        results.append({
                            "id": row[0],
                            "author": row[1],
                            "content": row[2],
                            "image": row[3],
                            "timestamp": row[4],
                            "likes": row[5]
                        })

            return self.send_json_response(200, {"results": results})

        else:
            return self.send_json_response(404, {"error": "Endpoint not found"})


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    """Threading TCP Server allows concurrent handling of requests natively in Python."""
    allow_reuse_address = True


if __name__ == '__main__':
    # Initialize SQLite Database & Tables on Startup
    init_db()

    if not PYWEBPUSH_AVAILABLE:
        print("[!] Warning: pywebpush library is not installed.")
        print("[!] Run: 'pip install pywebpush' to enable background cryptographic pushes.")

    with ReusableThreadingTCPServer((HOST, PORT), SoshalRequestHandler) as httpd:
        print(f"[*] Threaded SQLite-backed Soshal API Server running at http://{HOST}:{PORT}")
        print("[*] Waiting for concurrent connections...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")
            httpd.server_close()