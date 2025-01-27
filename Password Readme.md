# Password Manager

## Overview
This Password Manager is a simple application that allows users to securely store, retrieve, and delete passwords for various websites. It uses SQLite for database management and the `cryptography` library for encrypting passwords.

## Features
- Generate and store an encryption key.
- Add new passwords to the database.
- Retrieve stored passwords securely.
- Delete passwords from the database.
- User-friendly GUI built with Tkinter.

## Requirements
- Python 3.x
- `cryptography` library
- `tkinter` (comes pre-installed with Python)

## Installation
1. Clone the repository or download the `password_manager.py` file.
2. Install the required library using pip:
   ```bash
   pip install cryptography
   ```

## Usage
1. Run the application:
   ```bash
   python password_manager.py
   ```
2. The GUI will open, allowing you to add, retrieve, or delete passwords.

## Code Explanation

### Key Generation and Loading
- **generate_key()**: This function generates a new encryption key and saves it to a file named `key.key`. It is designed to run only once to create the key.
- **load_key()**: This function loads the encryption key from the `key.key` file for use in encrypting and decrypting passwords.

### Database Initialization
- **initialize_db()**: This function initializes the SQLite database and creates a table named `credentials` if it does not already exist. The table has columns for `id`, `website`, `username`, and `password`.

### Database Operations
- **add_password_to_db(website, username, password)**: This function encrypts the password using the loaded encryption key and stores the website, username, and encrypted password in the database.
- **retrieve_password_from_db(website)**: This function retrieves the username and encrypted password for a given website from the database.
- **delete_password_from_db(website)**: This function deletes the credentials associated with a specified website from the database.

### GUI Functions
- **add_password()**: This function prompts the user to enter a website, username, and password. If all fields are filled, it calls `add_password_to_db()` to store the information and shows a success message.
- **retrieve_password()**: This function prompts the user for a website and retrieves the associated credentials. It decrypts the password and displays it in a message box.
- **delete_password()**: This function prompts the user for a website and deletes the associated credentials if they exist, showing a success message.

### Main Application
- **main()**: This function sets up the main Tkinter window, adds buttons for adding, retrieving, and deleting passwords, and starts the Tkinter event loop.

## License
This project is licensed under the MIT License.

## Acknowledgments
- The `cryptography` library for secure encryption.
- SQLite for lightweight database management.
- Tkinter for creating the GUI.