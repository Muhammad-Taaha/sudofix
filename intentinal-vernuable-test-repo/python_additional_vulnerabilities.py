"""
Additional Python SAST Vulnerabilities
More security issues for comprehensive testing
"""

import xml.etree.ElementTree as ET
import yaml
import tempfile
import ldap
from Crypto.Cipher import DES
from Crypto.Hash import MD5
import jwt

# Vulnerability 1: XML External Entity (XXE) Injection
def parse_xml_unsafe(xml_string):
    # No protection against XXE attacks
    parser = ET.XMLParser()
    tree = ET.fromstring(xml_string, parser=parser)
    return tree

# Vulnerability 2: YAML Unsafe Load
def load_config_unsafe(config_file):
    with open(config_file, 'r') as f:
        # yaml.load without Loader is unsafe
        config = yaml.load(f)
    return config

# Vulnerability 3: LDAP Injection
def ldap_search_user(username):
    # User input directly in LDAP query
    ldap_conn = ldap.initialize('ldap://localhost:389')
    search_filter = f"(uid={username})"  # Vulnerable to injection
    results = ldap_conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, search_filter)
    return results

# Vulnerability 4: Weak Cipher (DES)
def encrypt_weak(data, key):
    # DES is cryptographically broken
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted = cipher.encrypt(data)
    return encrypted

# Vulnerability 5: Insecure JWT
def create_token_insecure(user_id):
    # Using 'none' algorithm
    token = jwt.encode({'user_id': user_id}, None, algorithm='none')
    return token

# Vulnerability 6: Race Condition (TOCTOU)
def check_and_use_file(filename):
    import os
    # Time-of-check to time-of-use race condition
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return f.read()

# Vulnerability 7: Insecure Temporary File
def create_temp_file():
    # Predictable temporary file name
    temp_file = "/tmp/myapp_temp_12345.txt"
    with open(temp_file, 'w') as f:
        f.write("sensitive data")
    return temp_file

# Vulnerability 8: Certificate Validation Disabled
def make_request_insecure():
    import requests
    # SSL verification disabled
    response = requests.get('https://example.com', verify=False)
    return response.text

# Vulnerability 9: Server-Side Request Forgery (SSRF)
def fetch_url(url):
    import urllib.request
    # No URL validation, allows SSRF
    response = urllib.request.urlopen(url)
    return response.read()

# Vulnerability 10: Insufficient Entropy
def generate_password():
    import random
    import string
    # Using weak random for security-critical function
    return ''.join(random.choice(string.ascii_letters) for _ in range(8))

# Vulnerability 11: Directory Traversal in Archive
def extract_archive(archive_path):
    import tarfile
    # No path validation during extraction
    with tarfile.open(archive_path) as tar:
        tar.extractall('/')  # Dangerous!

# Vulnerability 12: Format String Vulnerability
def log_message(user_input):
    # Using % formatting with user input
    message = "User action: %s" % user_input
    print(message)

# Vulnerability 13: Insecure Random for Security
def generate_session_id():
    import random
    # random module not suitable for security
    return random.randint(100000, 999999)

# Vulnerability 14: Null Cipher
def encrypt_null(data):
    from Crypto.Cipher import ARC2
    # Using weak ARC2 cipher
    key = b'weak_key'
    cipher = ARC2.new(key, ARC2.MODE_ECB)
    return cipher.encrypt(data)

# Vulnerability 15: Mass Assignment
class User:
    def __init__(self, data):
        # Directly assigning all attributes from input
        self.__dict__.update(data)

# Vulnerability 16: Unvalidated Redirect
def redirect_user(url):
    from flask import redirect
    # No URL validation
    return redirect(url)

# Vulnerability 17: XPath Injection
def xpath_query(username):
    import lxml.etree as etree
    xml_doc = etree.parse('users.xml')
    # Unsafe XPath query
    query = f"//user[@name='{username}']"
    return xml_doc.xpath(query)

# Vulnerability 18: Weak SSL/TLS Configuration
def create_ssl_context():
    import ssl
    # Using deprecated SSL protocol
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

# Vulnerability 19: SQL Injection (Blind)
def check_user_exists(username):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable to blind SQL injection
    query = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()[0] > 0

# Vulnerability 20: Code Injection via exec()
def execute_code(code_string):
    # Never use exec with user input
    exec(code_string)

# Vulnerability 21: Open Redirect via Header Injection
def redirect_with_header(location):
    # Header injection vulnerability
    return f"Location: {location}\n\n"

# Vulnerability 22: Inadequate Padding in Encryption
def encrypt_no_padding(data, key):
    from Crypto.Cipher import AES
    # No padding, vulnerable to various attacks
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

# Vulnerability 23: Information Exposure in Logs
def log_user_action(username, password, credit_card):
    import logging
    # Logging sensitive information
    logging.info(f"User {username} with password {password} used card {credit_card}")

# Vulnerability 24: Uncontrolled Resource Consumption
def process_user_data(data_size):
    # No limit on resource allocation
    buffer = bytearray(data_size)  # Can cause DoS
    return buffer

# Vulnerability 25: Use of Hard-coded IP Address
def connect_to_server():
    import socket
    # Hard-coded internal IP
    server = '192.168.1.100'
    port = 8080
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, port))
    return sock
