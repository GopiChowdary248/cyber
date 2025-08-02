#!/usr/bin/env python3
"""
Vulnerable Flask Application for SAST Testing
This application contains intentional security vulnerabilities for testing purposes.
DO NOT USE IN PRODUCTION!
"""

import os
import subprocess
import sqlite3
import pickle
import hashlib
import base64
from flask import Flask, request, render_template_string
from werkzeug.utils import secure_filename

app = Flask(__name__)

# VULNERABILITY: Hardcoded credentials
DB_PASSWORD = "password123"
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "super-secret-key-change-in-production"

# VULNERABILITY: Weak crypto - MD5
def hash_password(password):
    """Hash password using MD5 (VULNERABLE)"""
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY: Insecure deserialization
def deserialize_data(data):
    """Deserialize data using pickle (VULNERABLE)"""
    return pickle.loads(data)

@app.route('/')
def index():
    return 'Vulnerable Flask App - DO NOT USE IN PRODUCTION!'

@app.route('/login', methods=['POST'])
def login():
    """VULNERABILITY: SQL Injection"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # VULNERABILITY: SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)  # VULNERABLE: Direct string interpolation
    user = cursor.fetchone()
    
    if user:
        return "Login successful"
    else:
        return "Login failed"

@app.route('/execute')
def execute_command():
    """VULNERABILITY: Command Injection"""
    command = request.args.get('cmd')
    
    # VULNERABILITY: Command injection with shell=True
    result = subprocess.check_output(command, shell=True)  # VULNERABLE
    return result

@app.route('/file')
def read_file():
    """VULNERABILITY: Path Traversal"""
    filename = request.args.get('file')
    
    # VULNERABILITY: Path traversal - no validation
    with open(filename, 'r') as f:  # VULNERABLE: Direct file access
        return f.read()

@app.route('/eval')
def evaluate_code():
    """VULNERABILITY: Code Injection"""
    code = request.args.get('code')
    
    # VULNERABILITY: eval usage
    result = eval(code)  # VULNERABLE: eval with user input
    return str(result)

@app.route('/template')
def render_template():
    """VULNERABILITY: Server-Side Template Injection"""
    template = request.args.get('template')
    
    # VULNERABILITY: Template injection
    return render_template_string(template)  # VULNERABLE: Direct template rendering

@app.route('/upload', methods=['POST'])
def upload_file():
    """VULNERABILITY: Insecure File Upload"""
    if 'file' not in request.files:
        return 'No file uploaded'
    
    file = request.files['file']
    if file.filename == '':
        return 'No file selected'
    
    # VULNERABILITY: No file type validation
    filename = file.filename  # VULNERABLE: No sanitization
    file.save(os.path.join('/tmp', filename))  # VULNERABLE: Direct save
    
    return f'File {filename} uploaded successfully'

@app.route('/redirect')
def redirect():
    """VULNERABILITY: Open Redirect"""
    url = request.args.get('url')
    
    # VULNERABILITY: Open redirect
    return f'<script>window.location="{url}";</script>'  # VULNERABLE: Direct redirect

@app.route('/xss')
def xss():
    """VULNERABILITY: Cross-Site Scripting (XSS)"""
    user_input = request.args.get('input')
    
    # VULNERABILITY: XSS - direct output without escaping
    return f'<h1>User input: {user_input}</h1>'  # VULNERABLE: No HTML escaping

@app.route('/debug')
def debug_info():
    """VULNERABILITY: Information Disclosure"""
    # VULNERABILITY: Information disclosure
    debug_info = {
        'database_password': DB_PASSWORD,
        'api_key': API_KEY,
        'secret_key': SECRET_KEY,
        'environment': os.environ,
        'current_user': os.getenv('USER'),
        'hostname': os.uname().nodename
    }
    
    return debug_info

@app.route('/weak_crypto')
def weak_crypto():
    """VULNERABILITY: Weak Cryptography"""
    password = request.args.get('password')
    
    # VULNERABILITY: Base64 encoding for password storage
    encoded = base64.b64encode(password.encode()).decode()  # VULNERABLE: Base64 is not encryption
    
    return f'Encoded password: {encoded}'

@app.route('/insecure_headers')
def insecure_headers():
    """VULNERABILITY: Missing Security Headers"""
    response = app.make_response('Response without security headers')
    
    # VULNERABILITY: Missing security headers
    # response.headers['X-Frame-Options'] = 'DENY'  # Missing
    # response.headers['X-Content-Type-Options'] = 'nosniff'  # Missing
    # response.headers['X-XSS-Protection'] = '1; mode=block'  # Missing
    
    return response

@app.route('/race_condition')
def race_condition():
    """VULNERABILITY: Race Condition"""
    user_id = request.args.get('user_id')
    
    # VULNERABILITY: Race condition in file operations
    with open(f'/tmp/user_{user_id}.txt', 'w') as f:  # VULNERABLE: No locking
        f.write('user data')
    
    return 'User data written'

@app.route('/insecure_random')
def insecure_random():
    """VULNERABILITY: Insecure Random Number Generation"""
    import random
    
    # VULNERABILITY: Using random instead of secrets
    token = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=32))  # VULNERABLE
    
    return f'Generated token: {token}'

@app.route('/buffer_overflow_simulation')
def buffer_overflow_simulation():
    """VULNERABILITY: Buffer Overflow Simulation"""
    data = request.args.get('data', '')
    
    # VULNERABILITY: No input size validation
    if len(data) > 1000:  # VULNERABLE: Arbitrary limit
        return 'Data too large'
    
    # Simulate buffer overflow scenario
    buffer = bytearray(100)
    buffer[:len(data)] = data.encode()  # VULNERABLE: No bounds checking
    
    return f'Buffer filled with: {buffer[:len(data)].decode()}'

if __name__ == '__main__':
    # VULNERABILITY: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)  # VULNERABLE: Debug mode and 0.0.0.0 