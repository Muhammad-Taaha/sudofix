import os

BASE = "test_cases_for_sast/injection"

test_cases = {
    "command_os_system": {
        "vulnerable.py": """
import os

def vulnerable():
    user_input = input("Enter command: ")
    os.system(user_input)  # DANGEROUS
""",
        "safe.py": """
import subprocess

def safe():
    user_input = input("Enter filename: ")
    # SAFE: use subprocess with list, no shell
    subprocess.run(["ls", "-l", user_input])
""",
        "README.md": "# Command Injection via os.system\n\nVulnerable: user input passed to os.system\nSafe: using subprocess with list arguments",
    },
    "command_subprocess": {
        "vulnerable.py": """
import subprocess

def vulnerable():
    user_input = input("Enter command: ")
    subprocess.call(user_input, shell=True)  # DANGEROUS shell=True
""",
        "safe.py": """
import subprocess

def safe():
    user_input = input("Enter argument: ")
    subprocess.call(["ls", "-l", user_input])  # SAFE: list, no shell
""",
        "README.md": "# Command Injection via subprocess with shell=True",
    },
    "sql_concat": {
        "vulnerable.py": """
import sqlite3

def vulnerable():
    user_id = input("Enter user ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # DANGEROUS
""",
        "safe.py": """
import sqlite3

def safe():
    user_id = input("Enter user ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # SAFE parameterized
""",
        "README.md": "# SQL Injection via String Concatenation",
    },
    "sql_orm_raw": {
        "vulnerable.py": """
# Assume Django or SQLAlchemy in a real test
def vulnerable(request):
    user_input = request.GET.get('name')
    # Dangerous raw query with string formatting
    results = MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = '" + user_input + "'")
""",
        "safe.py": """
def safe(request):
    user_input = request.GET.get('name')
    # Safe: parameterized raw query
    results = MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = %s", [user_input])
""",
        "README.md": "# ORM Raw SQL Injection",
    },
    "code_eval": {
        "vulnerable.py": """
def vulnerable():
    user_code = input("Enter Python expression: ")
    result = eval(user_code)  # DANGEROUS
    print(result)
""",
        "safe.py": """
import ast

def safe():
    user_input = input("Enter a number: ")
    result = ast.literal_eval(user_input)  # SAFE
""",
        "README.md": "# Code Injection via eval/exec",
    },
    "ldap_injection": {
        "vulnerable.py": """
import ldap

def vulnerable():
    user_filter = input("Enter filter: ")
    conn = ldap.initialize("ldap://localhost")
    conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, user_filter)  # DANGEROUS
""",
        "safe.py": """
import ldap

def safe():
    user_filter = input("Enter filter: ")
    conn = ldap.initialize("ldap://localhost")
    safe_filter = ldap.filter.escape_filter_chars(user_filter)
    conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, f"(uid={safe_filter})")  # SAFE
""",
        "README.md": "# LDAP Injection",
    },
    "nosql_mongo": {
        "vulnerable.js": """
// JavaScript (Node.js) MongoDB vulnerable example
const userInput = req.query.username;
db.users.find({ $where: `this.username == '${userInput}'` });  // DANGEROUS
""",
        "safe.js": """
// Safe: use regular query object
const userInput = req.query.username;
db.users.find({ username: userInput });
""",
        "README.md": "# NoSQL Injection (MongoDB $where)",
    },
    "template_engine": {
        "vulnerable.py": """
from jinja2 import Template

def vulnerable():
    user_template = input("Enter template: ")
    t = Template(user_template)  # DANGEROUS: user-controlled template
    return t.render(name="test")
""",
        "safe.py": """
from jinja2 import Template

def safe():
    user_input = input("Enter name: ")
    t = Template("Hello {{ name }}")  # SAFE: fixed template
    return t.render(name=user_input)
""",
        "README.md": "# Server-Side Template Injection",
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
    print("Test cases generated successfully.")
