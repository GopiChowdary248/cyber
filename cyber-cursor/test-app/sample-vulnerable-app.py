#!/usr/bin/env python3
"""
Sample Vulnerable Application for Security Testing
This application contains intentional security vulnerabilities for testing purposes.
DO NOT USE IN PRODUCTION!
"""

import sqlite3
import os
import sys
from flask import Flask, request, render_template_string, jsonify
import subprocess
import pickle
import base64

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded credentials (SAST - Critical)
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "super_secret_token_123"

# VULNERABILITY 2: SQL Injection vulnerable function (SAST - High)
def get_user_data(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILITY 3: Command injection vulnerable function (SAST - High)
def execute_system_command(command):
    # VULNERABLE: Direct command execution
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

# VULNERABILITY 4: XSS vulnerable function (SAST - Medium)
def render_user_profile(username):
    # VULNERABLE: Direct template rendering without sanitization
    template = f"""
    <html>
        <head><title>User Profile</title></head>
        <body>
            <h1>Welcome {username}!</h1>
            <p>Your profile information:</p>
            <div>{username}</div>
        </body>
    </html>
    """
    return render_template_string(template)

# VULNERABILITY 5: Insecure deserialization (SAST - Critical)
def load_user_data(serialized_data):
    # VULNERABLE: Unsafe pickle deserialization
    return pickle.loads(base64.b64decode(serialized_data))

# VULNERABILITY 6: Path traversal vulnerable function (SAST - Medium)
def read_file(filename):
    # VULNERABLE: No path validation
    with open(filename, 'r') as f:
        return f.read()

# VULNERABILITY 7: Weak password validation (SAST - Low)
def validate_password(password):
    # VULNERABLE: Weak password requirements
    if len(password) >= 4:
        return True
    return False

# Flask Routes with vulnerabilities

@app.route('/')
def index():
    return render_template_string("""
    <html>
        <head><title>Vulnerable App</title></head>
        <body>
            <h1>Welcome to Vulnerable App</h1>
            <p>This is a test application with intentional security vulnerabilities.</p>
            <a href="/login">Login</a>
            <a href="/search">Search Users</a>
            <a href="/profile">Profile</a>
        </body>
    </html>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABILITY 8: Weak authentication (DAST - High)
        if username == 'admin' and password == 'admin':
            return "Login successful!"
        else:
            return "Login failed!"
    
    return render_template_string("""
    <html>
        <head><title>Login</title></head>
        <body>
            <h1>Login</h1>
            <form method="POST">
                <input type="text" name="username" placeholder="Username"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <input type="submit" value="Login">
            </form>
        </body>
    </html>
    """)

@app.route('/search')
def search_users():
    user_id = request.args.get('id')
    if user_id:
        # VULNERABILITY 9: SQL Injection in web interface (DAST - Critical)
        users = get_user_data(user_id)
        return jsonify(users)
    return "No user ID provided"

@app.route('/profile')
def profile():
    username = request.args.get('username', 'Guest')
    # VULNERABILITY 10: XSS in web interface (DAST - High)
    return render_user_profile(username)

@app.route('/command')
def execute_command():
    cmd = request.args.get('cmd')
    if cmd:
        # VULNERABILITY 11: Command injection in web interface (DAST - Critical)
        result = execute_system_command(cmd)
        return result
    return "No command provided"

@app.route('/file')
def read_file_route():
    filename = request.args.get('file')
    if filename:
        # VULNERABILITY 12: Path traversal in web interface (DAST - Medium)
        try:
            content = read_file(filename)
            return content
        except:
            return "File not found"
    return "No filename provided"

@app.route('/deserialize')
def deserialize_data():
    data = request.args.get('data')
    if data:
        # VULNERABILITY 13: Insecure deserialization in web interface (DAST - Critical)
        try:
            result = load_user_data(data)
            return str(result)
        except:
            return "Deserialization failed"
    return "No data provided"

@app.route('/api/users/<int:user_id>')
def api_get_user(user_id):
    # VULNERABILITY 14: Missing authentication (DAST - Medium)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return jsonify(user)

@app.route('/api/admin')
def admin_panel():
    # VULNERABILITY 15: Missing authorization (DAST - High)
    return jsonify({
        "admin": True,
        "users": ["user1", "user2", "user3"],
        "config": {"debug": True, "secret_key": "exposed_key"}
    })

@app.route('/api/data', methods=['POST'])
def store_data():
    # VULNERABILITY 16: No input validation (DAST - Medium)
    data = request.json
    return jsonify({"stored": True, "data": data})

@app.route('/debug')
def debug_info():
    # VULNERABILITY 17: Information disclosure (DAST - Low)
    return jsonify({
        "version": "1.0.0",
        "environment": "development",
        "database": "sqlite:///users.db",
        "debug": True,
        "secret_key": SECRET_TOKEN
    })

# VULNERABILITY 18: Insecure default configuration (SAST - Medium)
app.config['SECRET_KEY'] = 'default_secret_key'
app.config['DEBUG'] = True

if __name__ == '__main__':
    # VULNERABILITY 19: Running in debug mode (SAST - Low)
    app.run(debug=True, host='0.0.0.0', port=5000) 