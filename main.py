import mysql.connector
import bcrypt
import re

# Database configuration
DB_CONFIG = {
    'host': 'your_host',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'your_database'
}

# Establishes a connection to the MySQL database
def connect_to_db():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        print(f"Database connection error: {e}")
        return None

# Creates the MySQL user table if it does not exist
def create_user_table():
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    failed_attempts INT DEFAULT 0
                )
            ''')
            conn.commit()
            print("User table is ready.")
        except mysql.connector.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()

# Checks if a username is valid
def is_valid_username(username):
    return bool(re.match("^[A-Za-z0-9_]{3,20}$", username))

# Checks if a password is strong
def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', password))

# Registers a new user with a hashed password
def create_user(username, password):
    if not is_valid_username(username):
        raise ValueError("Invalid username. It should be 3-20 characters long and only contain letters, digits, or underscores.")

    if not is_strong_password(password):
        raise ValueError("Weak password. Ensure it's at least 8 characters with uppercase, lowercase, digit, and a special character.")

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, password_hash))
            conn.commit()
            return "User created successfully!"
        except mysql.connector.IntegrityError:
            raise ValueError("Username already exists. Please choose a different username.")
        except mysql.connector.Error as e:
            raise RuntimeError(f"Database error: {e}")
        finally:
            conn.close()

# Authenticates a user
def login_user(username, password):
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, failed_attempts FROM users WHERE username=%s', (username,))
            result = cursor.fetchone()

            if not result:
                raise ValueError("Username not found.")

            stored_hash, failed_attempts = result

            if failed_attempts >= 3:
                raise RuntimeError("Account locked due to multiple failed login attempts.")

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                cursor.execute('UPDATE users SET failed_attempts = 0 WHERE username=%s', (username,))
                conn.commit()
                return "Login successful!"
            else:
                cursor.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username=%s', (username,))
                conn.commit()
                raise ValueError("Incorrect password.")
        except mysql.connector.Error as e:
            raise RuntimeError(f"Database error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    create_user_table()