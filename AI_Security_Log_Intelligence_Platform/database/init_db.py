import sqlite3


conn = sqlite3.connect('users.db')

cursor = conn.cursor()


cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

print("Database and users table created successfully!")

conn.commit()
conn.close()
