import sqlite3

def vulnerable():
    user_id = input("Enter user ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # DANGEROUS: string concatenation
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
