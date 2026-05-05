import os

BASE = "test_cases_for_sast/injection"

test_cases = {
    "command_injection": {
        "vulnerable.py": """
import os
def vulnerable():
    user_cmd = input("Enter command: ")
    os.system(user_cmd)  # DANGEROUS
""",
        "safe.py": """
import os
def safe():
    # Constant command, safe (AST should ignore)
    os.system("ls -la")
""",
        "README.md": "# Command Injection: os.system with variable",
    },
    "command_subprocess": {
        "vulnerable.py": """
import subprocess
def vulnerable():
    user_cmd = input("Enter command: ")
    subprocess.call(user_cmd, shell=True)  # DANGEROUS
""",
        "safe.py": """
import subprocess
def safe():
    # List form, no shell, safe
    subprocess.call(["ls", "-la"])
""",
        "README.md": "# Command Injection: subprocess with shell=True",
    },
    "sql_concat": {
        "vulnerable.py": """
import sqlite3
def vulnerable():
    user_id = input("Enter ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # DANGEROUS
""",
        "safe.py": """
import sqlite3
def safe():
    user_id = input("Enter ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # Parameterized query, safe
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",
        "README.md": "# SQL Injection: string concatenation",
    },
    "sql_orm_raw": {
        "vulnerable.py": """
# Assume Django Model
def vulnerable(request):
    user_input = request.GET.get('name')
    # Raw query with concatenation
    return MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = '" + user_input + "'")
""",
        "safe.py": """
def safe(request):
    user_input = request.GET.get('name')
    # Parameterized raw query
    return MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = %s", [user_input])
""",
        "README.md": "# ORM Raw SQL Injection",
    },
    "code_eval": {
        "vulnerable.py": """
def vulnerable():
    user_code = input("Enter expression: ")
    result = eval(user_code)  # DANGEROUS
    print(result)
""",
        "safe.py": """
import ast
def safe():
    user_input = input("Enter a number: ")
    # Only literal evaluation, safe
    result = ast.literal_eval(user_input)
""",
        "README.md": "# Code Injection: eval",
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
// JavaScript vulnerable
const userInput = req.query.username;
db.users.find({ $where: `this.username == '${userInput}'` });  // DANGEROUS
""",
        "safe.js": """
// Safe: use regular query
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
    t = Template(user_template)  # DANGEROUS
    return t.render(name="test")
""",
        "safe.py": """
from jinja2 import Template
def safe():
    user_input = input("Enter name: ")
    t = Template("Hello {{ name }}")  # SAFE: template is constant
    return t.render(name=user_input)
""",
        "README.md": "# SSTI",
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
