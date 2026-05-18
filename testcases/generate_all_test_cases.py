import os

BASE = "test_cases_for_sast"

# ------------------------------------------------------------
# Helper to write files
# ------------------------------------------------------------
def write_test_case(category, subdir, files):
    path = os.path.join(BASE, category, subdir)
    os.makedirs(path, exist_ok=True)
    for filename, content in files.items():
        with open(os.path.join(path, filename), "w") as f:
            f.write(content.lstrip())
    print(f"Created {path}")

# ------------------------------------------------------------
# INJECTION (already exists, but we can add missing ones)
# ------------------------------------------------------------
# command_os_system, command_subprocess, etc. already exist.
# We add only new categories: command_injection already done.

# ------------------------------------------------------------
# AUTH (already generated, but we ensure all are present)
# ------------------------------------------------------------
# Already have: hardcoded_api_key, hardcoded_password,
# missing_auth_decorator, session_fixation, weak_password_hash
# We might add weak_password_hash with multi‑language.

# ------------------------------------------------------------
# CRYPTO
# ------------------------------------------------------------
crypto_rules = {
    "weak_hash": {
        "vulnerable.py": """
import hashlib
password = "secret"
hash_md5 = hashlib.md5(password.encode()).hexdigest()
hash_sha1 = hashlib.sha1(password.encode()).hexdigest()
print(hash_md5, hash_sha1)
""",
        "safe.py": """
import hashlib
password = "secret"
hash_sha256 = hashlib.sha256(password.encode()).hexdigest()
print(hash_sha256)
""",
        "vulnerable.java": """
import java.security.MessageDigest;
public class Test {
    public void hash() throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    }
}
""",
        "safe.java": """
import java.security.MessageDigest;
public class Test {
    public void hash() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    }
}
""",
        "vulnerable.js": """
const crypto = require('crypto');
const hash = crypto.createHash('md5').update('secret').digest('hex');
""",
        "safe.js": """
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('secret').digest('hex');
""",
        "vulnerable.go": """
package main
import "crypto/md5"
func main() {
    hash := md5.Sum([]byte("secret"))
    _ = hash
}
""",
        "safe.go": """
package main
import "crypto/sha256"
func main() {
    hash := sha256.Sum256([]byte("secret"))
    _ = hash
}
""",
        "README.md": "# Weak Hash Algorithms (MD5, SHA1)",
    },
    "hardcoded_key": {
        "vulnerable.py": """
SECRET_KEY = "my-super-secret-key-12345"
API_KEY = "abc123def456ghi789"
""",
        "safe.py": """
import os
SECRET_KEY = os.environ.get("SECRET_KEY")
API_KEY = os.getenv("API_KEY")
""",
        "vulnerable.java": """
public class Config {
    String SECRET_KEY = "my-secret";
}
""",
        "safe.java": """
public class Config {
    String SECRET_KEY = System.getenv("SECRET_KEY");
}
""",
        "vulnerable.js": """
const SECRET_KEY = "my-secret";
const API_KEY = "abc123";
""",
        "safe.js": """
const SECRET_KEY = process.env.SECRET_KEY;
const API_KEY = process.env.API_KEY;
""",
        "README.md": "# Hardcoded Cryptographic Keys",
    },
    "insecure_random": {
        "vulnerable.py": """
import random
rand_num = random.randint(1, 100)
rand_choice = random.choice(["a","b"])
""",
        "safe.py": """
import secrets
rand_num = secrets.randbelow(100)
""",
        "vulnerable.java": """
import java.util.Random;
Random rand = new Random();
int num = rand.nextInt(100);
""",
        "safe.java": """
import java.security.SecureRandom;
SecureRandom rand = new SecureRandom();
int num = rand.nextInt(100);
""",
        "vulnerable.js": """
let rand = Math.random();
""",
        "safe.js": """
const crypto = require('crypto');
let rand = crypto.randomBytes(4).readUInt32LE() / 0xffffffff;
""",
        "README.md": "# Insecure Random Number Generation",
    },
}

# ------------------------------------------------------------
# XSS
# ------------------------------------------------------------
xss_rules = {
    "dom_innerhtml": {
        "vulnerable.js": """
function displayUser() {
    let user = document.getElementById("user").value;
    document.getElementById("output").innerHTML = user;  // DANGEROUS
}
""",
        "safe.js": """
function displayUser() {
    let user = document.getElementById("user").value;
    document.getElementById("output").textContent = user;  // SAFE
}
""",
        "README.md": "# DOM XSS via innerHTML",
    },
    "reflected_xss": {
        "vulnerable.py": """
from flask import request, render_template_string
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string(f"<h1>Hello {name}</h1>")  # DANGEROUS
""",
        "safe.py": """
from flask import request, render_template
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template('hello.html', name=name)  # SAFE (auto-escaped)
""",
        "README.md": "# Reflected XSS (Flask)",
    },
    "unsafe_rendering": {
        "vulnerable.py": """
from django.utils.safestring import mark_safe
def show(request):
    user_input = request.GET.get('data')
    return mark_safe(user_input)  # DANGEROUS
""",
        "safe.py": """
from django.utils.html import escape
def show(request):
    user_input = request.GET.get('data')
    return escape(user_input)  # SAFE
""",
        "README.md": "# Unsafe Rendering (mark_safe, |safe)",
    },
    "stored_xss": {
        "vulnerable.py": """
from django.db import models
class Comment(models.Model):
    text = models.TextField()
def add_comment(request):
    comment = Comment(text=request.POST['comment'])  # DANGEROUS
    comment.save()
""",
        "safe.py": """
from django.utils.html import escape
def add_comment(request):
    safe_text = escape(request.POST['comment'])
    comment = Comment(text=safe_text)
    comment.save()
""",
        "README.md": "# Stored XSS (Unsanitized DB Input)",
    },
}

# ------------------------------------------------------------
# DESERIALIZATION
# ------------------------------------------------------------
deser_rules = {
    "pickle_load": {
        "vulnerable.py": """
import pickle
data = pickle.loads(user_input)  # DANGEROUS
""",
        "safe.py": """
import json
data = json.loads(user_input)  # SAFE
""",
        "README.md": "# Unsafe Pickle Deserialization",
    },
    "yaml_unsafe": {
        "vulnerable.py": """
import yaml
data = yaml.load(user_input)  # DANGEROUS (no SafeLoader)
""",
        "safe.py": """
import yaml
data = yaml.safe_load(user_input)  # SAFE
""",
        "vulnerable.java": """
Yaml yaml = new Yaml();
Object obj = yaml.load(userInput);
""",
        "safe.java": """
Yaml yaml = new Yaml(new SafeConstructor());
Object obj = yaml.load(userInput);
""",
        "README.md": "# Unsafe YAML Deserialization",
    },
    "java_objectinput": {
        "vulnerable.java": """
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Object obj = ois.readObject();
""",
        "safe.java": """
// Use safe alternatives like JSON or validated serialization
""",
        "README.md": "# Java ObjectInputStream Deserialization",
    },
    "gob_deserialize": {
        "vulnerable.go": """
import "encoding/gob"
dec := gob.NewDecoder(r)
var m map[string]interface{}
dec.Decode(&m)
""",
        "safe.go": """
import "encoding/json"
dec := json.NewDecoder(r)
var m map[string]interface{}
dec.Decode(&m)
""",
        "README.md": "# Go Gob Deserialization",
    },
}

# ------------------------------------------------------------
# NETWORK
# ------------------------------------------------------------
network_rules = {
    "ssrf": {
        "vulnerable.py": """
import requests
url = request.args.get('url')
response = requests.get(url)  # DANGEROUS
""",
        "safe.py": """
import requests
url = request.args.get('url')
if url.startswith(('http://example.com','https://example.com')):
    response = requests.get(url)
""",
        "vulnerable.js": """
const axios = require('axios');
const url = req.query.url;
axios.get(url);  // DANGEROUS
""",
        "safe.js": """
const allowed = ['https://api.example.com'];
if (allowed.includes(new URL(url).origin)) { axios.get(url); }
""",
        "README.md": "# SSRF",
    },
    "ssl_disabled": {
        "vulnerable.py": """
import requests
requests.get('https://example.com', verify=False)  # DANGEROUS
""",
        "safe.py": """
requests.get('https://example.com', verify=True)
""",
        "vulnerable.js": """
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
""",
        "safe.js": """
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
""",
        "README.md": "# SSL Verification Disabled",
    },
    "http_no_timeout": {
        "vulnerable.py": """
import requests
requests.get('https://example.com')  # DANGEROUS (no timeout)
""",
        "safe.py": """
requests.get('https://example.com', timeout=5)
""",
        "README.md": "# HTTP Request Without Timeout",
    },
}

# ------------------------------------------------------------
# DATA EXPOSURE
# ------------------------------------------------------------
data_exposure_rules = {
    "sensitive_log": {
        "vulnerable.py": """
import logging
password = "secret"
logging.info(f"User password: {password}")  # DANGEROUS
""",
        "safe.py": """
logging.info("User logged in")  # SAFE
""",
        "README.md": "# Logging Sensitive Information",
    },
    "stacktrace_leak": {
        "vulnerable.py": """
import traceback
try:
    1/0
except:
    traceback.print_exc()  # DANGEROUS
""",
        "safe.py": """
import logging
try:
    1/0
except Exception as e:
    logging.error("An error occurred", exc_info=False)
""",
        "README.md": "# Stacktrace Leak",
    },
}

# ------------------------------------------------------------
# BUSINESS LOGIC
# ------------------------------------------------------------
business_logic_rules = {
    "race_condition": {
        "vulnerable.py": """
import os
def update_file(data):
    with open("data.txt", "r") as f:
        content = f.read()
    new_content = content + data
    with open("data.txt", "w") as f:
        f.write(new_content)  # DANGEROUS (TOCTOU)
""",
        "safe.py": """
import fcntl
def update_file(data):
    with open("data.txt", "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        content = f.read()
        f.seek(0)
        f.write(content + data)
        f.truncate()
        fcntl.flock(f, fcntl.LOCK_UN)
""",
        "README.md": "# Race Condition (TOCTOU)",
    },
    "missing_rate_limit": {
        "vulnerable.py": """
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['user'])
    return "OK"  # DANGEROUS (no rate limiting)
""",
        "safe.py": """
from flask_limiter import Limiter
limiter = Limiter(app)
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    user = authenticate(request.form['user'])
    return "OK"
""",
        "README.md": "# Missing Rate Limiting",
    },
}

# ------------------------------------------------------------
# MISC
# ------------------------------------------------------------
misc_rules = {
    "dangerous_defaults": {
        "vulnerable.py": """
def add_item(item, items=[]):  # DANGEROUS
    items.append(item)
    return items
""",
        "safe.py": """
def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items
""",
        "README.md": "# Mutable Default Arguments",
    },
}

# ------------------------------------------------------------
# FRAMEWORK (already partly there, we add missing)
# ------------------------------------------------------------
framework_rules = {
    "django_debug_true": {
        "vulnerable.py": """
# settings.py
DEBUG = True  # DANGEROUS
""",
        "safe.py": """
import os
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
""",
        "README.md": "# Django DEBUG=True in Production",
    },
    "flask_debug_mode": {
        "vulnerable.py": """
app.run(debug=True)  # DANGEROUS
""",
        "safe.py": """
app.run(debug=False)
""",
        "README.md": "# Flask Debug Mode Enabled",
    },
    "spring_sql_injection": {
        "vulnerable.java": """
@Query("select u from User u where u.name = '" + name + "'")
List<User> findByName(String name);  // DANGEROUS
""",
        "safe.java": """
@Query("select u from User u where u.name = :name")
List<User> findByName(@Param("name") String name);
""",
        "README.md": "# Spring JPA SQL Injection",
    },
}

# ------------------------------------------------------------
# Generate all
# ------------------------------------------------------------
def generate_all():
    for category, rules in [
        ("crypto", crypto_rules),
        ("xss", xss_rules),
        ("deserialization", deser_rules),
        ("network", network_rules),
        ("data_exposure", data_exposure_rules),
        ("business_logic", business_logic_rules),
        ("misc", misc_rules),
        ("framework", framework_rules),
    ]:
        for rule_name, files in rules.items():
            write_test_case(category, rule_name, files)
    print("All test cases generated successfully.")

if __name__ == "__main__":
    generate_all()