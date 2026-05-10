# import os

# BASE = "test_cases_for_sast/injection"

# test_cases = {
#     "command_injection": {
#         "vulnerable.py": """
# import os
# def vulnerable():
#     user_cmd = input("Enter command: ")
#     os.system(user_cmd)  # DANGEROUS
# """,
#         "safe.py": """
# import os
# def safe():
#     # Constant command, safe (AST should ignore)
#     os.system("ls -la")
# """,
#         "README.md": "# Command Injection: os.system with variable",
#     },
#     "command_subprocess": {
#         "vulnerable.py": """
# import subprocess
# def vulnerable():
#     user_cmd = input("Enter command: ")
#     subprocess.call(user_cmd, shell=True)  # DANGEROUS
# """,
#         "safe.py": """
# import subprocess
# def safe():
#     # List form, no shell, safe
#     subprocess.call(["ls", "-la"])
# """,
#         "README.md": "# Command Injection: subprocess with shell=True",
#     },
#     "sql_concat": {
#         "vulnerable.py": """
# import sqlite3
# def vulnerable():
#     user_id = input("Enter ID: ")
#     conn = sqlite3.connect("db.sqlite")
#     cursor = conn.cursor()
#     cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # DANGEROUS
# """,
#         "safe.py": """
# import sqlite3
# def safe():
#     user_id = input("Enter ID: ")
#     conn = sqlite3.connect("db.sqlite")
#     cursor = conn.cursor()
#     # Parameterized query, safe
#     cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# """,
#         "README.md": "# SQL Injection: string concatenation",
#     },
#     "sql_orm_raw": {
#         "vulnerable.py": """
# # Assume Django Model
# def vulnerable(request):
#     user_input = request.GET.get('name')
#     # Raw query with concatenation
#     return MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = '" + user_input + "'")
# """,
#         "safe.py": """
# def safe(request):
#     user_input = request.GET.get('name')
#     # Parameterized raw query
#     return MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = %s", [user_input])
# """,
#         "README.md": "# ORM Raw SQL Injection",
#     },
#     "code_eval": {
#         "vulnerable.py": """
# def vulnerable():
#     user_code = input("Enter expression: ")
#     result = eval(user_code)  # DANGEROUS
#     print(result)
# """,
#         "safe.py": """
# import ast
# def safe():
#     user_input = input("Enter a number: ")
#     # Only literal evaluation, safe
#     result = ast.literal_eval(user_input)
# """,
#         "README.md": "# Code Injection: eval",
#     },
#     "ldap_injection": {
#         "vulnerable.py": """
# import ldap
# def vulnerable():
#     user_filter = input("Enter filter: ")
#     conn = ldap.initialize("ldap://localhost")
#     conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, user_filter)  # DANGEROUS
# """,
#         "safe.py": """
# import ldap
# def safe():
#     user_filter = input("Enter filter: ")
#     conn = ldap.initialize("ldap://localhost")
#     safe_filter = ldap.filter.escape_filter_chars(user_filter)
#     conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, f"(uid={safe_filter})")  # SAFE
# """,
#         "README.md": "# LDAP Injection",
#     },
#     "nosql_mongo": {
#         "vulnerable.js": """
# // JavaScript vulnerable
# const userInput = req.query.username;
# db.users.find({ $where: `this.username == '${userInput}'` });  // DANGEROUS
# """,
#         "safe.js": """
# // Safe: use regular query
# const userInput = req.query.username;
# db.users.find({ username: userInput });
# """,
#         "README.md": "# NoSQL Injection (MongoDB $where)",
#     },
#     "template_engine": {
#         "vulnerable.py": """
# from jinja2 import Template
# def vulnerable():
#     user_template = input("Enter template: ")
#     t = Template(user_template)  # DANGEROUS
#     return t.render(name="test")
# """,
#         "safe.py": """
# from jinja2 import Template
# def safe():
#     user_input = input("Enter name: ")
#     t = Template("Hello {{ name }}")  # SAFE: template is constant
#     return t.render(name=user_input)
# """,
#         "README.md": "# SSTI",
#     },
# }


# def create_test_cases():
#     for rule, files in test_cases.items():
#         rule_dir = os.path.join(BASE, rule)
#         os.makedirs(rule_dir, exist_ok=True)
#         for filename, content in files.items():
#             filepath = os.path.join(rule_dir, filename)
#             with open(filepath, "w") as f:
#                 f.write(content.lstrip())
#         print(f"Created {rule_dir}")


# if __name__ == "__main__":
#     create_test_cases()
#     print("Test cases generated successfully.")


import os

BASE = "test_cases_for_sast/file_related"   # adjust as needed

test_cases = {
    "path_traversal_open": {
        "vulnerable.py": """
import os

def vulnerable():
    user_file = input("Enter file name: ")
    with open(user_file, 'r') as f:   # DANGEROUS
        return f.read()
""",
        "safe.py": """
import os

def safe():
    user_file = input("Enter file name: ")
    # Only allow alphanumeric filenames
    if user_file.isalnum():
        with open(user_file, 'r') as f:
            return f.read()
    return "Invalid filename"
""",
        "README.md": "# Path Traversal: open() with user input",
    },
    "insecure_permissions": {
        "vulnerable.py": """
import os

def vulnerable():
    os.chmod("/tmp/secret.txt", 0o777)   # DANGEROUS (world writable)
""",
        "safe.py": """
import os

def safe():
    os.chmod("/tmp/secret.txt", 0o600)   # Owner read/write only
""",
        "README.md": "# Insecure Permissions: chmod 0o777",
    },
    "tempfile_race": {
        "vulnerable.py": """
import tempfile

def vulnerable():
    filename = tempfile.mktemp()   # DANGEROUS (race condition)
    with open(filename, 'w') as f:
        f.write("data")
""",
        "safe.py": """
import tempfile

def safe():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("data")
        filename = f.name
""",
        "README.md": "# Insecure Temporary File: mktemp",
    },
    "unsafe_upload": {
        "vulnerable.py": """
from flask import request

def upload():
    file = request.files['user_file']
    file.save("/uploads/" + file.filename)   # DANGEROUS (no validation)
    return "ok"
""",
        "safe.py": """
import os
from werkzeug.utils import secure_filename

def upload():
    file = request.files['user_file']
    filename = secure_filename(file.filename)
    if filename and allowed_file(filename):
        file.save(os.path.join("/uploads", filename))
    return "ok"
""",
        "README.md": "# Unsafe File Upload: no validation",
    },
    "hardcoded_secrets": {
        "vulnerable.py": """
API_KEY = "abc123def456ghi789jkl012mno345"
PASSWORD = "SuperSecret789!"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
""",
        "safe.py": """
import os
API_KEY = os.environ.get("API_KEY")
PASSWORD = os.environ.get("DB_PASSWORD")
AWS_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY")
""",
        "README.md": "# Hardcoded Secrets",
    },
    "weak_crypto": {
        "vulnerable.py": """
import hashlib

def vulnerable():
    password = "secret"
    hash_md5 = hashlib.md5(password.encode()).hexdigest()   # WEAK
    hash_sha1 = hashlib.sha1(password.encode()).hexdigest() # WEAK
    return hash_md5, hash_sha1
""",
        "safe.py": """
import hashlib

def safe():
    password = "secret"
    hash_sha256 = hashlib.sha256(password.encode()).hexdigest()   # STRONG
    return hash_sha256
""",
        "README.md": "# Weak Cryptographic Hash (MD5/SHA1)",
    },
    "xss": {
        "vulnerable.js": """
function vulnerable() {
    let user = document.getElementById("user").value;
    document.getElementById("output").innerHTML = user;   // DANGEROUS
}
""",
        "safe.js": """
function safe() {
    let user = document.getElementById("user").value;
    document.getElementById("output").textContent = user;   // SAFE
}
""",
        "README.md": "# XSS via innerHTML",
    },
}

def create_test_cases():
    for rule, files in test_cases.items():
        rule_dir = os.path.join(BASE, rule)
        os.makedirs(rule_dir, exist_ok=True)
        for filename, content in files.items():
            filepath = os.path.join(rule_dir, filename)
            with open(filepath, "w") as f:
                f.write(content.lstrip())
        print(f"Created {rule_dir}")

if __name__ == "__main__":
    create_test_cases()
    print("File‑related test cases generated successfully.")