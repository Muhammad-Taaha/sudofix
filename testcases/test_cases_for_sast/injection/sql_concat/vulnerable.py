import sqlite3
def vulnerable():
    user_id = input("Enter ID: ")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # DANGEROUS
