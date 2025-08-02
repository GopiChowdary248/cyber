#!/usr/bin/env python3
"""
Sample Flask Application with Intentional Security Vulnerabilities
For SAST Tool Testing Purposes

This application contains various security vulnerabilities for testing:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Hardcoded Credentials
- Insecure Deserialization
- Path Traversal
- Weak Authentication
- Information Disclosure
"""

from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for
import sqlite3
import subprocess
import pickle
import os
import base64
import hashlib
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'hardcoded_secret_key_12345'  # VULNERABILITY: Hardcoded secret key

# VULNERABILITY: Hardcoded database credentials
DB_USERNAME = "admin"
DB_PASSWORD = "password123"
DB_HOST = "localhost"

# VULNERABILITY: Hardcoded API keys
API_KEY = "sk-1234567890abcdef"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Initialize database
def init_db():
    """Initialize SQLite database with vulnerable schema"""
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: SQL injection prone table creation
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            title TEXT,
            content TEXT,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                  ('admin', 'admin123', 'admin@example.com', 1))
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
                  ('user1', 'password123', 'user1@example.com', 0))
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Home page with XSS vulnerability"""
    user_input = request.args.get('name', '')
    
    # VULNERABILITY: XSS - Direct template injection
    template = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
        <h1>Welcome {user_input}!</h1>
        <p>This is a vulnerable application for SAST testing.</p>
        <a href="/login">Login</a>
        <a href="/search">Search</a>
        <a href="/upload">Upload</a>
    </body>
    </html>
    """
    return render_template_string(template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with SQL injection vulnerability"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABILITY: SQL Injection - direct string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['is_admin'] = user[4]
                return redirect(url_for('dashboard'))
            else:
                return "Invalid credentials", 401
        except Exception as e:
            return f"Error: {str(e)}", 500
        finally:
            conn.close()
    
    return '''
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/search')
def search():
    """Search functionality with SQL injection"""
    query = request.args.get('q', '')
    
    if query:
        # VULNERABILITY: SQL Injection - direct string concatenation
        sql_query = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
        
        conn = sqlite3.connect('vulnerable.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute(sql_query)
            results = cursor.fetchall()
            return jsonify(results)
        except Exception as e:
            return f"Error: {str(e)}", 500
        finally:
            conn.close()
    
    return "No query provided"

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """File upload with path traversal vulnerability"""
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file uploaded", 400
        
        file = request.files['file']
        filename = file.filename
        
        # VULNERABILITY: Path Traversal - no validation
        upload_path = os.path.join('/tmp/uploads', filename)
        
        # VULNERABILITY: Command Injection - using user input in shell command
        os.system(f'mkdir -p /tmp/uploads && chmod 777 /tmp/uploads')
        
        file.save(upload_path)
        return f"File uploaded to {upload_path}"
    
    return '''
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required><br>
        <input type="submit" value="Upload">
    </form>
    '''

@app.route('/execute')
def execute_command():
    """Command execution endpoint with command injection vulnerability"""
    command = request.args.get('cmd', '')
    
    if command:
        # VULNERABILITY: Command Injection - direct subprocess call
        try:
            result = subprocess.check_output(command, shell=True, text=True)
            return result
        except subprocess.CalledProcessError as e:
            return f"Error: {str(e)}", 500
    
    return "No command provided"

@app.route('/deserialize')
def deserialize_data():
    """Data deserialization with pickle vulnerability"""
    data = request.args.get('data', '')
    
    if data:
        try:
            # VULNERABILITY: Insecure Deserialization - using pickle
            decoded_data = base64.b64decode(data)
            deserialized = pickle.loads(decoded_data)
            return f"Deserialized: {deserialized}"
        except Exception as e:
            return f"Error: {str(e)}", 500
    
    return "No data provided"

@app.route('/api/users')
def get_users():
    """API endpoint with information disclosure"""
    # VULNERABILITY: Information Disclosure - exposing sensitive data
    users_data = {
        'users': [
            {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'password_hash': 'abc123'},
            {'id': 2, 'username': 'user1', 'email': 'user1@example.com', 'password_hash': 'def456'}
        ],
        'api_key': API_KEY,
        'aws_credentials': {
            'access_key': AWS_ACCESS_KEY,
            'secret_key': AWS_SECRET_KEY
        }
    }
    return jsonify(users_data)

@app.route('/dashboard')
def dashboard():
    """Dashboard with weak authentication"""
    # VULNERABILITY: Weak Authentication - no proper session validation
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    username = session['username']
    is_admin = session.get('is_admin', 0)
    
    # VULNERABILITY: SQL Injection in dashboard query
    query = f"SELECT * FROM posts WHERE user_id = {user_id}"
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)
        posts = cursor.fetchall()
        
        template = f"""
        <h1>Dashboard for {username}</h1>
        <p>User ID: {user_id}</p>
        <p>Admin: {is_admin}</p>
        <h2>Your Posts:</h2>
        <ul>
        """
        
        for post in posts:
            template += f"<li>{post[1]} - {post[2]}</li>"
        
        template += "</ul>"
        
        if is_admin:
            template += '<p><a href="/admin">Admin Panel</a></p>'
        
        return template
    except Exception as e:
        return f"Error: {str(e)}", 500
    finally:
        conn.close()

@app.route('/admin')
def admin_panel():
    """Admin panel with weak authorization"""
    # VULNERABILITY: Weak Authorization - simple boolean check
    if not session.get('is_admin'):
        return "Access denied", 403
    
    # VULNERABILITY: Information Disclosure - exposing all data
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    cursor.execute("SELECT * FROM posts")
    posts = cursor.fetchall()
    
    conn.close()
    
    return f"""
    <h1>Admin Panel</h1>
    <h2>All Users:</h2>
    <pre>{users}</pre>
    <h2>All Posts:</h2>
    <pre>{posts}</pre>
    """

@app.route('/config')
def show_config():
    """Configuration endpoint with information disclosure"""
    # VULNERABILITY: Information Disclosure - exposing configuration
    config = {
        'database': {
            'host': DB_HOST,
            'username': DB_USERNAME,
            'password': DB_PASSWORD
        },
        'api_keys': {
            'openai': API_KEY,
            'aws_access': AWS_ACCESS_KEY,
            'aws_secret': AWS_SECRET_KEY
        },
        'app_secret': app.secret_key,
        'debug_mode': app.debug
    }
    return jsonify(config)

@app.route('/hash')
def hash_password():
    """Password hashing with weak algorithm"""
    password = request.args.get('password', '')
    
    if password:
        # VULNERABILITY: Weak Hashing - using MD5
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        
        # VULNERABILITY: Weak Hashing - using SHA1
        sha1_hash = hashlib.sha1(password.encode()).hexdigest()
        
        return jsonify({
            'password': password,
            'md5_hash': md5_hash,
            'sha1_hash': sha1_hash
        })
    
    return "No password provided"

@app.route('/eval')
def evaluate_code():
    """Code evaluation with eval vulnerability"""
    code = request.args.get('code', '')
    
    if code:
        # VULNERABILITY: Code Injection - using eval
        try:
            result = eval(code)
            return f"Result: {result}"
        except Exception as e:
            return f"Error: {str(e)}", 500
    
    return "No code provided"

@app.route('/exec')
def execute_code():
    """Code execution with exec vulnerability"""
    code = request.args.get('code', '')
    
    if code:
        # VULNERABILITY: Code Injection - using exec
        try:
            exec(code)
            return "Code executed successfully"
        except Exception as e:
            return f"Error: {str(e)}", 500
    
    return "No code provided"

@app.route('/debug')
def debug_info():
    """Debug endpoint with information disclosure"""
    # VULNERABILITY: Information Disclosure - exposing debug information
    debug_info = {
        'request_headers': dict(request.headers),
        'request_args': dict(request.args),
        'request_form': dict(request.form),
        'session_data': dict(session),
        'environment_vars': {
            'FLASK_ENV': os.getenv('FLASK_ENV'),
            'FLASK_DEBUG': os.getenv('FLASK_DEBUG'),
            'SECRET_KEY': app.secret_key
        }
    }
    return jsonify(debug_info)

if __name__ == '__main__':
    init_db()
    # VULNERABILITY: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=5000) 