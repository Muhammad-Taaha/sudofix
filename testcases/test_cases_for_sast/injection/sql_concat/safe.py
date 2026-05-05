import sqlite3
def safe():
    user_id = input("Enter ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # Parameterized query, safe
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
