import sqlite3

def safe():
    user_id = input("Enter user ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # SAFE parameterized
