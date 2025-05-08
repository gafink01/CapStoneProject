# Import necessary libraries
import mysql.connector  # Allows Python to connect to a MySQL database
import bcrypt  # Used for securely hashing passwords before storing them
import re  # Provides regular expression support for validating usernames and passwords
import tkinter as tk  # GUI library for creating graphical user interfaces
from tkinter import messagebox  # Module from tkinter used to display pop-up messages


DB_CONFIG = {
    'host': 'localhost',
    'user': 'gafink01',
    'password': 'gafink01',
    'database': 'PythonFinal'
}


def connect_to_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as e:
        messagebox.showerror("Database Error", f"Database connection error: {e}")
        return None


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
            messagebox.showerror("Database Error", f"Database error: {e}")
        finally:
            conn.close()


def is_valid_username(username):
    return bool(re.match("^[A-Za-z0-9_]{3,20}$", username))

#
def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', password))


def create_user(username, password):
    if not is_valid_username(username):
        messagebox.showerror("Error", "Invalid username. Use 3-20 characters: letters, digits, or underscores.")
        return
    if not is_strong_password(password):  
        messagebox.showerror("Error", "Weak password. Use at least 8 characters, including uppercase, lowercase, a digit, and a special character.")
        return


    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)', (username, password_hash))
            conn.commit()
            messagebox.showinfo("Success", "User created successfully!")
            list_users()
        except mysql.connector.IntegrityError:
            messagebox.showerror("Error", "Username already exists. Please choose a different username.")
        except mysql.connector.Error as e:
            messagebox.showerror("Database Error", f"Database error: {e}")
        finally:
            conn.close()


def remove_user(username):
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE username=%s', (username,))
            conn.commit()
            messagebox.showinfo("Success", f"User '{username}' removed successfully!")  # Displays success message
            list_users()
        except mysql.connector.Error as e:
            messagebox.showerror("Database Error", f"Database error: {e}")
        finally:
            conn.close()


def list_users():
    conn = connect_to_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username FROM users')
            users = cursor.fetchall()
            user_list.delete(0, tk.END)
            for user in users:
                user_list.insert(tk.END, f"ID: {user[0]}, Username: {user[1]}")
        except mysql.connector.Error as e:  # Handles database errors
            messagebox.showerror("Database Error", f"Database error: {e}")
        finally:
            conn.close()


root = tk.Tk()
root.title("PythonFinal")
root.geometry("1000x1000")


tk.Label(root, text="Username:").pack()
username_entry = tk.Entry(root)
username_entry.pack()


tk.Label(root, text="Password:").pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()


tk.Button(root, text="Add User", command=lambda: create_user(username_entry.get(), password_entry.get())).pack()
tk.Button(root, text="Remove User", command=lambda: remove_user(username_entry.get())).pack()
tk.Button(root, text="List Users", command=list_users).pack()


user_list = tk.Listbox(root, width=100)
user_list.pack()


create_user_table()
list_users()
root.mainloop()