import webbrowser
import threading
from flask import Flask, render_template, request, redirect, url_for, flash
import hashlib

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for flashing warning messages

# Global password list and maximum limit
password_list = []
PASSWORD_LIMIT = 256

# Function to hash passwords using a selected hash algorithm
def hash_passwords(password_list, hash_function):
    hashed_passwords = []
    for password in password_list:
        if hash_function == 'MD5':
            hashed_password = hashlib.md5(password.encode()).hexdigest()
        elif hash_function == 'SHA256':
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
        elif hash_function == 'SHA512':
            hashed_password = hashlib.sha512(password.encode()).hexdigest()
        elif hash_function == 'SHA1':
            hashed_password = hashlib.sha1(password.encode()).hexdigest()
        hashed_passwords.append(hashed_password)
    return hashed_passwords

# Route for the main page
@app.route("/", methods=["GET", "POST"])
def index():
    global password_list
    hashed_passwords = []
    hash_function = request.form.get("hash_function", "MD5")

    if request.method == "POST":
        # Get form data
        password = request.form.get("password_entry", "").strip()

        # Check for duplicate passwords
        if password in password_list:
            flash("Duplicate password! Passwords must be unique.", "error")
        elif password and len(password_list) < PASSWORD_LIMIT:
            password_list.append(password)
        elif len(password_list) >= PASSWORD_LIMIT:
            flash(f"Cannot add more than {PASSWORD_LIMIT} passwords.", "error")

    # Hash the passwords using the selected algorithm
    hashed_passwords = hash_passwords(password_list, hash_function)

    return render_template(
        "index.html",
        password_list=password_list,
        hashed_passwords=hashed_passwords,
        password_limit=PASSWORD_LIMIT,
        zip=zip,
        hash_function=hash_function,
    )

# Route to delete selected passwords
@app.route("/remove_passwords", methods=["POST"])
def remove_passwords():
    global password_list
    selected_passwords = request.form.getlist("password_checkbox")  # Get selected passwords from checkboxes
    password_list = [password for password in password_list if password not in selected_passwords]  # Remove them from list
    return redirect(url_for('index'))

# Route to clear all passwords
@app.route("/clear_passwords")
def clear_passwords():
    global password_list
    password_list = []
    return redirect(url_for('index'))

# Function to automatically open the browser when the server starts
def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000/")

if __name__ == "__main__":
    # Run the browser opener in a separate thread so it doesn't block the server
    threading.Timer(1, open_browser).start()
    app.run(debug=True)
