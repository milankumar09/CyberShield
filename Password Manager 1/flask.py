import sqlite3
from cryptography.fernet import Fernet
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel


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
    results = cursor.fetchall()  # Fetch all credentials for the website
    connection.close()
    return results  # Return all results

def delete_password_from_db(website, username):
    connection = sqlite3.connect("passwords.db")
    cursor = connection.cursor()
    cursor.execute("""
        DELETE FROM credentials
        WHERE website = ? AND username = ?
    """, (website, username))  # Specify username for deletion
    connection.commit()
    connection.close()

# Custom Dialog for Adding Password
def add_password_dialog():
    dialog = Toplevel()
    dialog.title("Add Password")
    dialog.geometry("300x250")
    dialog.configure(bg="#f0f0f0")

    tk.Label(dialog, text="Enter Website:", bg="#f0f0f0").pack(pady=5)
    website_entry = tk.Entry(dialog, width=30)
    website_entry.pack(pady=5)

    tk.Label(dialog, text="Enter Username:", bg="#f0f0f0").pack(pady=5)
    username_entry = tk.Entry(dialog, width=30)
    username_entry.pack(pady=5)

    tk.Label(dialog, text="Enter Password:", bg="#f0f0f0").pack(pady=5)
    password_entry = tk.Entry(dialog, show='*', width=30)
    password_entry.pack(pady=5)

    # Checkbox to toggle password visibility
    def toggle_password_visibility():
        if password_entry.cget('show') == '*':
            password_entry.config(show='')
            show_password_var.set(True)
        else:
            password_entry.config(show='*')
            show_password_var.set(False)

    show_password_var = tk.BooleanVar()
    show_password_checkbox = tk.Checkbutton(dialog, text="Show Password", variable=show_password_var, command=toggle_password_visibility, bg="#f0f0f0")
    show_password_checkbox.pack(pady=5)

    def save_password():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        
        if website and username and password:
            add_password_to_db(website, username, password)
            messagebox.showinfo("Success", f"Password for {username} on {website} added successfully!")
            dialog.destroy()
        else:
            messagebox.showerror("Error", "All fields are required!")

    tk.Button(dialog, text="Save", command=save_password, bg="#4CAF50", fg="white").pack(pady=10)
    dialog.transient(root)
    dialog.grab_set()
    root.wait_window(dialog)

# Custom Dialog for Retrieving Password
def retrieve_password_dialog():
    dialog = Toplevel()
    dialog.title("Retrieve Password")
    dialog.geometry("300x150")
    dialog.configure(bg="#f0f0f0")

    tk.Label(dialog, text="Enter Website:", bg="#f0f0f0").pack(pady=5)
    website_entry = tk.Entry(dialog, width=30)
    website_entry.pack(pady=5)

    def get_password():
        website = website_entry.get()
        if website:
            results = retrieve_password_from_db(website)  # Get all results
            if results:
                message = f"Credentials for {website}:\n"
                for username, encrypted_password in results:
                    decrypted_password = cipher.decrypt(encrypted_password).decode()
                    message += f"Username: {username}, Password: {decrypted_password}\n"
                messagebox.showinfo("Passwords Retrieved", message)
            else:
                messagebox.showerror("Error", f"No credentials found for {website}!")
            dialog.destroy()
        else:
            messagebox.showerror("Error", "Website is required!")

    tk.Button(dialog, text="Retrieve", command=get_password, bg="#2196F3", fg="white").pack(pady=10)
    dialog.transient(root)
    dialog.grab_set()
    root.wait_window(dialog)

# Custom Dialog for Deleting Password
def delete_password_dialog():
    dialog = Toplevel()
    dialog.title("Delete Password")
    dialog.geometry("300x200")
    dialog.configure(bg="#f0f0f0")

    tk.Label(dialog, text="Enter Website:", bg="#f0f0f0").pack(pady=5)
    website_entry = tk.Entry(dialog, width=30)
    website_entry.pack(pady=5)

    tk.Label(dialog, text="Enter Username:", bg="#f0f0f0").pack(pady=5)
    username_entry = tk.Entry(dialog, width=30)
    username_entry.pack(pady=5)

    def delete_password():
        website = website_entry.get()
        username = username_entry.get()
        
        if website and username:
            result = retrieve_password_from_db(website)
            if result:
                delete_password_from_db(website, username)  # Pass username for deletion
                messagebox.showinfo("Success", f"Credentials for {username} on {website} deleted.")
                dialog.destroy()
            else:
                messagebox.showerror("Error", f"No credentials found for {website}!")
        else:
            messagebox.showerror("Error", "Website and username are required!")

    tk.Button(dialog, text="Delete", command=delete_password, bg="#f44336", fg="white").pack(pady=10)
    dialog.transient(root)
    dialog.grab_set()
    root.wait_window(dialog)

# Main Application
def main():
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("400x400")  # Increased height for better layout
    root.configure(bg="#f0f0f0")  # Set background color

    # Create a frame for better layout
    frame = tk.Frame(root, bg="#ffffff", padx=20, pady=20)
    frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    tk.Label(frame, text="Password Manager", font=("Helvetica", 20, "bold"), bg="#ffffff").pack(pady=10)

    # Add buttons with improved styling
    tk.Button(frame, text="Add Password", width=25, command=add_password_dialog, bg="#4CAF50", fg="white", font=("Helvetica", 12)).pack(pady=5)
    tk.Button(frame, text="Retrieve Password", width=25, command=retrieve_password_dialog, bg="#2196F3", fg="white", font=("Helvetica", 12)).pack(pady=5)
    tk.Button(frame, text="Delete Password", width=25, command=delete_password_dialog, bg="#f44336", fg="white", font=("Helvetica", 12)).pack(pady=5)
    tk.Button(frame, text="Exit", width=25, command=root.quit, bg="#9E9E9E", fg="white", font=("Helvetica", 12)).pack(pady=10)

    # Add a footer label
    tk.Label(frame, text="Secure your passwords safely!", bg="#ffffff", font=("Helvetica", 10)).pack(side=tk.BOTTOM, pady=10)

    root.mainloop()

if __name__ == "__main__":
    initialize_db()  # Ensure the database is initialized
    main()







