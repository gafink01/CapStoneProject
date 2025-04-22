import sqlite3
import bcrypt

def create_user_database():
    conn = sqlite3.connect('user_database.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL)''')
    conn.commit()
    conn.close()
    print("Database created and users table is ready.")

def setup_dependencies():
    try:
        import bcrypt
        print("All dependencies are installed.")
    except ImportError:
        print("Please install bcrypt using: pip install bcrypt")

def register_user(username, password):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn = sqlite3.connect('user_database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        return "User registered successfully!"
    except sqlite3.IntegrityError:
        return "Username already exists. Please choose a different username."

if __name__ == "__main__":
    create_user_database()

    setup_dependencies()

    print(register_user("example_user", "secure_password123"))