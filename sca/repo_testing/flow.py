import requests
import pickle
import subprocess
import os
from flask import Flask, render_template_string

app = Flask(__name__)

# Vulnerable: Using eval() - High severity
def process_user_input(user_data):
    result = eval(user_data)  # VULNERABLE: eval allows arbitrary code execution
    return result

# Vulnerable: Using pickle.loads() - High severity
def deserialize_data(data):
    return pickle.loads(data)  # VULNERABLE: pickle can execute arbitrary code

# Vulnerable: Using subprocess without proper escaping - High severity
def execute_command(cmd):
    subprocess.call(cmd, shell=True)  # VULNERABLE: shell=True allows command injection

# Vulnerable: Using os.system() - High severity
def run_system_command(command):
    os.system(command)  # VULNERABLE: os.system is vulnerable to injection

# Vulnerable: Using exec() - High severity
def execute_code(code_string):
    exec(code_string)  # VULNERABLE: exec allows arbitrary code execution

# Vulnerable: SQL Injection pattern
def fetch_user_data(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"  # VULNERABLE: string concatenation
    return query

# Vulnerable: Flask template injection
@app.route('/render')
def render_template_injection(user_input):
    return render_template_string(user_input)  # VULNERABLE: template injection

# Vulnerable: Weak random for security
import random
def generate_token():
    return random.randint(0, 999999)  # VULNERABLE: random is not cryptographically secure

# Vulnerable: Using requests without timeout
def fetch_external_data(url):
    r = requests.get(url)  # VULNERABLE: no timeout can cause hanging
    return r.text

# Vulnerable: Hardcoded credentials
DB_PASSWORD = "admin123"  # VULNERABLE: hardcoded credentials
API_KEY = "sk-1234567890abcdef"  # VULNERABLE: hardcoded API key

if __name__ == "__main__":
    app.run(debug=True)  # VULNERABLE: debug=True in production is unsafe