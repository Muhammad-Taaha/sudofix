"""
Python SAST Vulnerabilities Demo
This file contains intentional security vulnerabilities for testing purposes
"""

import os
import pickle
import subprocess
import hashlib
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Hardcoded credentials
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "my-secret-token-12345"

# Vulnerability 2: SQL Injection
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Unsafe SQL query construction
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Vulnerability 3: Command Injection
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    # Unsafe command execution
    result = os.system(f"ping -c 4 {host}")
    return f"Ping result: {result}"

# Vulnerability 4: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('name')
    # No path validation
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# Vulnerability 5: Insecure Deserialization
@app.route('/load')
def load_data():
    data = request.args.get('data')
    # Unsafe pickle deserialization
    obj = pickle.loads(data.encode())
    return str(obj)

# Vulnerability 6: Weak Cryptography (MD5)
def hash_password(password):
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability 7: Using eval()
@app.route('/calc')
def calculate():
    expression = request.args.get('expr')
    # Never use eval with user input
    result = eval(expression)
    return str(result)

# Vulnerability 8: Insecure Random Number Generation
import random
def generate_token():
    # random is not cryptographically secure
    return ''.join(random.choice('0123456789abcdef') for _ in range(32))

# Vulnerability 9: XSS Vulnerability
@app.route('/search')
def search():
    query = request.args.get('q')
    # No output encoding
    return f"<h1>Search results for: {query}</h1>"

# Vulnerability 10: Subprocess with shell=True
@app.route('/execute')
def execute_command():
    cmd = request.args.get('cmd')
    # shell=True is dangerous with user input
    output = subprocess.check_output(cmd, shell=True)
    return output

if __name__ == '__main__':
    # Debug mode in production
    app.run(debug=True, host='0.0.0.0')
