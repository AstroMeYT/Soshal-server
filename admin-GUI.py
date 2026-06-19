import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import json
import os
import glob
from datetime import datetime

# --- Configuration ---
USERS_FILE = 'users.json'
POSTS_DIR = 'posts'

class SoshalAdminPanel:
    def __init__(self, root):
        self.root = root
        self.root.title("Soshal Server Admin Panel")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        self.users_data = {}
        self.current_selected_user = None
        self.current_user_posts = [] # Stores tuples of (filepath, post_dict)
        
        self.setup_ui()
        self.load_data()

    def setup_ui(self):
        # --- Left Panel (User List & Search) ---
        left_frame = tk.Frame(self.root, padx=10, pady=10, width=250)
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        left_frame.pack_propagate(False) # Maintain width

        tk.Label(left_frame, text="Registered Users", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Search Bar
        search_frame = tk.Frame(left_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Label(search_frame, text="Search:", font=("Arial", 9)).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        
        # FIX: Updated for Python 3.14 / Tcl 9 compatibility
        self.search_var.trace_add("write", self.filter_users)
        
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        # Scrollbar and Listbox for Users
        list_frame = tk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.user_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=("Arial", 11))
        self.user_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.user_listbox.yview)
        
        self.user_listbox.bind('<<ListboxSelect>>', self.on_user_select)

        # Refresh Button
        tk.Button(left_frame, text="Refresh Data", command=self.load_data).pack(fill=tk.X, pady=(5, 0))

        # --- Right Panel (Controls & Posts) ---
        self.right_frame = tk.Frame(self.root, padx=20, pady=10)
        self.right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # --- 1. User Controls Center ---
        controls_frame = tk.Frame(self.right_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(controls_frame, text="User Controls", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # Username Display & Suffix ID & Rename
        tk.Label(controls_frame, text="Username:", font=("Arial", 10)).pack(anchor=tk.W)
        name_frame = tk.Frame(controls_frame)
        name_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.lbl_username_val = tk.Label(name_frame, text="Select a user...", font=("Arial", 11, "italic"), fg="gray")
        self.lbl_username_val.pack(side=tk.LEFT)
        
        # Unique User ID Suffix label placed directly next to the username
        self.lbl_userid_val = tk.Label(name_frame, text="", font=("Arial", 11, "bold"), fg="#8b5cf6")
        self.lbl_userid_val.pack(side=tk.LEFT, padx=(5, 0))
        
        self.btn_rename = tk.Button(name_frame, text="Rename User", state=tk.DISABLED, command=self.rename_user)
        self.btn_rename.pack(side=tk.RIGHT)

        # Password Hash Display
        tk.Label(controls_frame, text="Password Hash (PBKDF2):", font=("Arial", 10)).pack(anchor=tk.W)
        pass_frame = tk.Frame(controls_frame)
        pass_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.entry_password = tk.Entry(pass_frame, show="*", font=("Arial", 10), state="readonly")
        self.entry_password.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.btn_toggle_pass = tk.Button(pass_frame, text="Show", state=tk.DISABLED, command=self.toggle_password)
        self.btn_toggle_pass.pack(side=tk.RIGHT)

        # Stats & Delete Button
        stats_frame = tk.Frame(controls_frame)
        stats_frame.pack(fill=tk.X, pady=(5, 10))
        self.lbl_stats = tk.Label(stats_frame, text="Posts: 0 | Followers: 0 | Following: 0", font=("Arial", 10))
        self.lbl_stats.pack(side=tk.LEFT)

        self.btn_delete = tk.Button(stats_frame, text="Delete User & ALL Posts", bg="#ffcccc", fg="#cc0000", font=("Arial", 10, "bold"), state=tk.DISABLED, command=self.delete_user)
        self.btn_delete.pack(side=tk.RIGHT)

        tk.Frame(self.right_frame, height=2, bd=1, relief=tk.SUNKEN).pack(fill=tk.X, pady=10)

        # --- 2. User Posts List Section ---
        tk.Label(self.right_frame, text="User's Posts History", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        posts_list_frame = tk.Frame(self.right_frame)
        posts_list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        post_scroll = tk.Scrollbar(posts_list_frame)
        post_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.posts_listbox = tk.Listbox(posts_list_frame, yscrollcommand=post_scroll.set, font=("Courier", 10))
        self.posts_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        post_scroll.config(command=self.posts_listbox.yview)

    def filter_users(self, *args):
        """Filters the user list based on the search bar input."""
        query = self.search_var.get().lower()
        self.user_listbox.delete(0, tk.END)
        for username in sorted(self.users_data.keys()):
            if query in username.lower():
                self.user_listbox.insert(tk.END, username)

    def load_data(self):
        """Loads users.json into memory and repopulates the lists."""
        if not os.path.exists(USERS_FILE):
            messagebox.showerror("Error", f"Could not find {USERS_FILE}. Ensure you are running this in the server directory.")
            return

        with open(USERS_FILE, 'r') as f:
            self.users_data = json.load(f)

        self.filter_users() # Applies current search filter to new data
        self.clear_details()

    def load_user_posts(self, username):
        """Finds every post made by the user and loads it into the listbox."""
        self.posts_listbox.delete(0, tk.END)
        self.current_user_posts.clear()

        if not os.path.exists(POSTS_DIR):
            return

        # Gather all posts
        for filepath in glob.glob(os.path.join(POSTS_DIR, '*.json')):
            try:
                with open(filepath, 'r') as f:
                    post = json.load(f)
                if post.get('author') == username:
                    self.current_user_posts.append((filepath, post))
            except Exception:
                pass

        # Sort posts newest to oldest
        self.current_user_posts.sort(key=lambda x: x[1].get('timestamp', 0), reverse=True)

        # Populate listbox
        for idx, (filepath, post) in enumerate(self.current_user_posts):
            ts = post.get('timestamp', 0)
            date_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            
            # Clean up content for preview
            content_snippet = post.get('content', '').replace('\n', ' ')
            if len(content_snippet) > 60:
                content_snippet = content_snippet[:57] + "..."
            if not content_snippet and post.get('image'):
                content_snippet = "[IMAGE POST]"
                
            display_str = f"[{date_str}] ID: {post.get('id', '???')[:8]}... | {content_snippet}"
            self.posts_listbox.insert(tk.END, display_str)

    def on_user_select(self, event):
        """Handles selecting a user from the list."""
        selection = self.user_listbox.curselection()
        if not selection:
            return
            
        username = self.user_listbox.get(selection[0])
        self.current_selected_user = username
        user_info = self.users_data[username]

        # Update UI Controls
        self.lbl_username_val.config(text=username, font=("Arial", 12, "bold"), fg="black")
        
        # Display the loaded User ID
        user_id = user_info.get('user_id', 'N/A')
        self.lbl_userid_val.config(text=f"#{user_id}")
        
        self.entry_password.config(state=tk.NORMAL)
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, user_info.get('password_hash', 'Unknown'))
        self.entry_password.config(state="readonly", show="*")
        self.btn_toggle_pass.config(text="Show")
        
        # Load posts first so we can accurately count them
        self.load_user_posts(username)
        
        followers = len(user_info.get('followers', []))
        following = len(user_info.get('following', []))
        posts_count = len(self.current_user_posts)
        
        self.lbl_stats.config(text=f"Posts: {posts_count} | Followers: {followers} | Following: {following}")

        # Enable buttons
        self.btn_rename.config(state=tk.NORMAL)
        self.btn_toggle_pass.config(state=tk.NORMAL)
        self.btn_delete.config(state=tk.NORMAL)

    def clear_details(self):
        """Resets the entire right panel."""
        self.current_selected_user = None
        self.lbl_username_val.config(text="Select a user...", font=("Arial", 11, "italic"), fg="gray")
        self.lbl_userid_val.config(text="")
        
        self.entry_password.config(state=tk.NORMAL)
        self.entry_password.delete(0, tk.END)
        self.entry_password.config(state="readonly", show="*")
        
        self.lbl_stats.config(text="Posts: 0 | Followers: 0 | Following: 0")
        
        self.btn_rename.config(state=tk.DISABLED)
        self.btn_toggle_pass.config(state=tk.DISABLED, text="Show")
        self.btn_delete.config(state=tk.DISABLED)
        
        self.posts_listbox.delete(0, tk.END)
        self.current_user_posts.clear()

    def toggle_password(self):
        """Toggles the visibility of the password hash entry."""
        if self.entry_password.cget('show') == '*':
            self.entry_password.config(show='')
            self.btn_toggle_pass.config(text="Hide")
        else:
            self.entry_password.config(show='*')
            self.btn_toggle_pass.config(text="Show")

    def rename_user(self):
        """Safely renames a user and cascades the change everywhere."""
        old_name = self.current_selected_user
        if not old_name: return

        new_name = simpledialog.askstring("Rename User", f"Enter new username for '{old_name}':", parent=self.root)
        
        if not new_name or new_name.strip() == "" or new_name == old_name:
            return
            
        new_name = new_name.strip()
        if new_name in self.users_data:
            messagebox.showerror("Error", "That username is already taken.")
            return

        # 1. Update Users Dictionary Key
        self.users_data[new_name] = self.users_data.pop(old_name)

        # 2. Cascade: Update all followers/following lists
        for user, data in self.users_data.items():
            if 'followers' in data and old_name in data['followers']:
                data['followers'].remove(old_name)
                data['followers'].append(new_name)
            if 'following' in data and old_name in data['following']:
                data['following'].remove(old_name)
                data['following'].append(new_name)

        # 3. Save users.json
        with open(USERS_FILE, 'w') as f:
            json.dump(self.users_data, f, indent=4)

        # 4. Cascade: Update Posts
        posts_updated = 0
        if os.path.exists(POSTS_DIR):
            for filepath in glob.glob(os.path.join(POSTS_DIR, '*.json')):
                try:
                    with open(filepath, 'r') as f:
                        post = json.load(f)
                    
                    if post.get('author') == old_name:
                        post['author'] = new_name
                        with open(filepath, 'w') as f:
                            json.dump(post, f, indent=4)
                        posts_updated += 1
                except Exception as e:
                    print(f"Error updating post {filepath}: {e}")

        messagebox.showinfo("Success", f"User renamed to '{new_name}'.\nUpdated {posts_updated} posts.")
        self.load_data()

    def delete_user(self):
        """Completely obliterates a user, their network, and their posts."""
        target = self.current_selected_user
        if not target: return

        # Ask for confirmation
        confirm = messagebox.askyesno("WARNING", f"Are you sure you want to PERMANENTLY delete '{target}'?\n\nThis will instantly delete their account and EVERY post they have ever made. This cannot be undone.", icon='warning')
        
        if not confirm: return

        # 1. Cascade: Remove from all followers/following lists
        for user, data in self.users_data.items():
            if 'followers' in data and target in data['followers']:
                data['followers'].remove(target)
            if 'following' in data and target in data['following']:
                data['following'].remove(target)

        # 2. Delete from users dictionary
        del self.users_data[target]

        # 3. Save users.json
        with open(USERS_FILE, 'w') as f:
            json.dump(self.users_data, f, indent=4)

        # 4. Cascade: Delete all their posts
        posts_deleted = 0
        if os.path.exists(POSTS_DIR):
            for filepath in glob.glob(os.path.join(POSTS_DIR, '*.json')):
                try:
                    with open(filepath, 'r') as f:
                        post = json.load(f)
                    
                    if post.get('author') == target:
                        os.remove(filepath)
                        posts_deleted += 1
                except Exception:
                    pass

        messagebox.showinfo("Deleted", f"User '{target}' has been deleted.\n{posts_deleted} posts were permanently removed.")
        self.load_data()

if __name__ == "__main__":
    root = tk.Tk()
    app = SoshalAdminPanel(root)
    root.mainloop()