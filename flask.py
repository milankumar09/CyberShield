import sqlite3
from cryptography.fernet import Fernet
import os
import tkinter as tk
from tkinter import messagebox, simpledialog


# Generate a key and save it for encryption (Run once)
def generate_key():
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
generate_key()

# Load the encryption key
def load_key():
    with open("key.key", "rb") as key_file:
        return key_file.read()

encryption_key = load_key()
cipher = Fernet(encryption_key)

# Initialize the database
def initialize_db():
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    connection.commit()
    connection.close()

initialize_db()

# Database operations
def add_password_to_db(website, username, password):
    encrypted_password = cipher.encrypt(password.encode())
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO credentials (website, username, password)
        VALUES (?, ?, ?)
    """, (website, username, encrypted_password))
    connection.commit()
    connection.close()

def retrieve_password_from_db(website):
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    cursor.execute("""
        SELECT username, password FROM credentials
        WHERE website = ?
    """, (website,))
    result = cursor.fetchone()
    connection.close()
    return result

def delete_password_from_db(website):
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    cursor.execute("""
        DELETE FROM credentials
        WHERE website = ?
    """, (website,))
    connection.commit()
    connection.close()

# GUI Functions
def add_password():
    website = simpledialog.askstring("Add Password", "Enter website:")
    username = simpledialog.askstring("Add Password", "Enter username:")
    password = simpledialog.askstring("Add Password", "Enter password:")
    
    if website and username and password:
        add_password_to_db(website, username, password)
        messagebox.showinfo("Success", f"Password for {website} added successfully!")
    else:
        messagebox.showerror("Error", "All fields are required!")

def retrieve_password():
    website = simpledialog.askstring("Retrieve Password", "Enter website:")
    
    if website:
        result = retrieve_password_from_db(website)
        if result:
            username, encrypted_password = result
            decrypted_password = cipher.decrypt(encrypted_password).decode()
            messagebox.showinfo("Password Retrieved", f"Website: {website}\nUsername: {username}\nPassword: {decrypted_password}")
        else:
            messagebox.showerror("Error", f"No credentials found for {website}!")
    else:
        messagebox.showerror("Error", "Website is required!")

def delete_password():
    website = simpledialog.askstring("Delete Password", "Enter website:")
    
    if website:
        result = retrieve_password_from_db(website)
        if result:
            delete_password_from_db(website)
            messagebox.showinfo("Success", f"Credentials for {website} deleted.")
        else:
            messagebox.showerror("Error", f"No credentials found for {website}!")
    else:
        messagebox.showerror("Error", "Website is required!")

# Main Application
def main():
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("300x200")

    tk.Label(root, text="Password Manager", font=("Helvetica", 16)).pack(pady=10)
    
    tk.Button(root, text="Add Password", width=20, command=add_password).pack(pady=5)
    tk.Button(root, text="Retrieve Password", width=20, command=retrieve_password).pack(pady=5)
    tk.Button(root, text="Delete Password", width=20, command=delete_password).pack(pady=5)
    tk.Button(root, text="Exit", width=20, command=root.quit).pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    main()







