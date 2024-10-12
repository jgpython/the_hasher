import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font

# Global password list and maximum limit
password_list = []
PASSWORD_LIMIT = 256  # Limiting the total passwords to 256

# Function to show the instructions in a larger window
def show_intro():
    intro_text = """
    ██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗██████╗ 
    ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
    ███████║███████║███████╗███████║█████╗  ██████╔╝
    ██╔══██║██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗
    ██║  ██║██║  ██║███████║██║  ██║███████╗██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    
    ** Welcome to the Password Hashing Tool – The Hasher! **

    This tool allows you to:
    - Enter passwords manually or load them from a text file.
    - Select different hashing algorithms: MD5, SHA256, SHA512, or SHA1.
    - Dynamically view hashed passwords in a table as they are added.
    - Save the results to a file (hash only or both password and hash).

    Instructions:
    1. Use the "Enter Passwords Manually" or "Load Passwords from File" options to add passwords.
    2. Select a hashing algorithm to apply to the passwords.
    3. Use the "Save to File" button to download the results.

    Password Limit: You can upload a maximum of 256 passwords.

    Enjoy your secure password management experience!
    – Created by jgpython
    """
    instruction_window = tk.Toplevel(root)
    instruction_window.title("Instructions")
    instruction_window.geometry("700x500")  
    instruction_window.configure(bg="black")

    # Adding a text widget to display the instructions
    instruction_text = tk.Text(instruction_window, wrap=tk.WORD, bg="black", fg="#a0ff80", font=("Courier", 10))
    instruction_text.insert(tk.END, intro_text)
    instruction_text.config(state=tk.DISABLED)
    instruction_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Update the password counter in the app (useful to know how many are added)
def update_password_counter():
    counter_label.config(text=f"Passwords: {len(password_list)}/{PASSWORD_LIMIT}")

# Function to add password from the entry box and validate input
def add_password_from_entry(event=None):
    password = password_entry.get().strip()  # Removing any extra spaces
    if ' ' in password:
        messagebox.showerror("Invalid Input", "Password cannot contain spaces.")  # Alert if password has spaces
    elif password:
        if len(password_list) >= PASSWORD_LIMIT:  # Stop if we hit the password limit
            messagebox.showwarning("Limit Exceeded", f"Cannot add more than {PASSWORD_LIMIT} passwords.")
            return
        password_list.append(str(password))  # Ensure all passwords are stored as strings
        password_entry.delete(0, tk.END)  # Clear the entry box after adding
        update_and_hash_table()  # Update the table immediately after adding
        update_password_counter()  # Show updated password count
    else:
        messagebox.showerror("Invalid Input", "Password cannot be empty or spaces only.")  # Catch empty input
    update_add_button_state()  # Enable/disable the add button based on validity

# Enable/disable the Add Password button based on whether the entry is valid
def update_add_button_state(*args):
    password = password_entry.get().strip()
    if password and ' ' not in password:
        add_button.config(state=tk.NORMAL)
    else:
        add_button.config(state=tk.DISABLED)

# Load passwords from a file
def load_passwords_from_file():
    file_path = filedialog.askopenfilename(title="Select Password File", filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, 'r') as f:  # Read the file safely
                loaded_passwords = [line.strip() for line in f.readlines() if line.strip() and ' ' not in line]  # Skip any empty or invalid lines
                if len(password_list) + len(loaded_passwords) > PASSWORD_LIMIT:  # Enforce the limit
                    messagebox.showwarning("Limit Exceeded", f"Cannot load more than {PASSWORD_LIMIT} passwords.")
                    return
                password_list.extend([str(p) for p in loaded_passwords])  # Ensure all loaded passwords are strings
                messagebox.showinfo("Success", f"Loaded {len(loaded_passwords)} valid passwords from {file_path}")
                update_and_hash_table()  # Update the table with loaded passwords
                update_password_counter()  # Update the counter
        except FileNotFoundError:
            messagebox.showerror("Error", f"File {file_path} not found.")  # Catch file not found errors
    else:
        messagebox.showerror("Error", "No file selected.")

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
        hashed_passwords.append(hashed_password)  # Collect all hashed passwords in the list
    return hashed_passwords

# Update the table with the hashed passwords
def update_table(password_list, hashed_passwords):
    for i in tree.get_children():  # Clear the old entries
        tree.delete(i)
    
    # Insert new password and hash values
    for password, hashed in zip(password_list, hashed_passwords):
        tree.insert('', 'end', values=(password, hashed))
    
    # Set the column sizes to fit even long SHA512 hashes and ensure readability
    tree.column('Password', width=300)  # Fixed width for the password column
    tree.column('Hash', width=900)  # Wider width for the hash column to fit long hashes

# Automatically update and hash when adding or modifying passwords
def update_and_hash_table():
    if password_list:
        hash_function = hash_function_var.get()  # Get the selected hash function
        hashed_passwords = hash_passwords(password_list, hash_function)
        update_table(password_list, hashed_passwords)  # Update the table with the hashes
    else:
        tree.delete(*tree.get_children())  # Clear table if no passwords

# Remove the selected password from the list
def remove_password():
    selected_item = tree.selection()
    if selected_item:
        selected_password = tree.item(selected_item)['values'][0]  # Get the password from the selected row
        if str(selected_password) in password_list:
            password_list.remove(str(selected_password))  # Remove it from the list, ensuring it's treated as a string
            tree.delete(selected_item)  # Remove the selected item from the table as well
            update_password_counter()  # Update the counter after removal
        else:
            messagebox.showerror("Error", "Selected password is not found in the list.")
    else:
        messagebox.showerror("Error", "Please select a password to remove.")  # Prompt to select something

# Function to copy the hash value of the selected row
def copy_hash():
    selected_item = tree.selection()
    if selected_item:
        hash_value = tree.item(selected_item)['values'][1]  # Get the hash value from the selected row
        root.clipboard_clear()
        root.clipboard_append(hash_value)  # Copy the hash value to the clipboard
        messagebox.showinfo("Copied", "Hash value copied to clipboard!")
    else:
        messagebox.showerror("Error", "Please select a row to copy the hash.")

# Save the table contents (passwords and hashes) to a file, only if there are entries
def save_to_file():
    if not password_list:
        messagebox.showerror("Error", "No passwords to save.")  # Prevent saving an empty file
        return
    
    def save_option(option):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                for row in tree.get_children():
                    password, hash_value = tree.item(row)['values']
                    if option == 'Both':
                        file.write(f"{password}: {hash_value}\n")
                    elif option == 'Hash':
                        file.write(f"{hash_value}\n")
            messagebox.showinfo("Success", f"Data saved to {file_path}")
        save_dialog.destroy()

    save_dialog = tk.Toplevel(root)
    save_dialog.title("Save Options")
    save_dialog.geometry("300x150")
    save_dialog.configure(bg="black")
    tk.Label(save_dialog, text="Choose what to save:", bg="black", fg="#a0ff80").pack(pady=10)

    tk.Button(save_dialog, text="Save Both Password and Hash", command=lambda: save_option('Both'), bg="#404040", fg="white").pack(pady=5)
    tk.Button(save_dialog, text="Save Only Hash", command=lambda: save_option('Hash'), bg="#404040", fg="white").pack(pady=5)

# Styling the buttons, labels, and other UI elements to match the theme
def style_application():
    style = ttk.Style()
    style.configure('TButton', font=('Arial', 12), padding=6)
    style.configure('TLabel', font=('Arial', 12))
    style.configure('TCombobox', font=('Arial', 12))

# Update table dynamically when hash function changes
def on_hash_function_change(event):
    update_and_hash_table()

# Main app setup
root = tk.Tk()
root.title("the_hasher")  
root.geometry("1450x800")  # Increase window size to fit all elements
root.configure(bg="black")

# Apply styles
style = ttk.Style()  # Define the style object for the Treeview
style_application()

# Organizing the layout of the app
main_frame = tk.Frame(root, bg="black")
main_frame.pack(pady=20, padx=20)

# Table to show passwords and their hashed values
tree = ttk.Treeview(main_frame, columns=("Password", "Hash"), show="headings", height=10)
tree.heading("Password", text="Password")
tree.heading("Hash", text="Hashed Value")

# Apply styles for readability and better grid lines
style.configure("Treeview", rowheight=25, fieldbackground="black", background="black", foreground="#a0ff80", font=('Arial', 12))  # Larger font size for readability
style.configure("Treeview.Heading", font=("Arial", 12, "bold"), background="#f0f0f0", foreground="black")  # Changed heading color for visibility (black font on light background)
style.map('Treeview', background=[('selected', '#404040')], foreground=[('selected', 'white')])

# Set fixed size for columns to fit long hash values
tree.column('Password', width=300)
tree.column('Hash', width=1100)

tree.pack(pady=20, fill=tk.BOTH, expand=True)

# Bottom section for Save, Instructions, and other buttons
button_frame = tk.Frame(main_frame, bg="black")
button_frame.pack(side=tk.BOTTOM, pady=10)

# Counter for passwords
counter_label = tk.Label(main_frame, text="Passwords: 0/256", fg="#a0ff80", bg="black", font=('Arial', 12))
counter_label.pack(pady=10)

# List Options Frame
list_frame = tk.LabelFrame(button_frame, text="List Options", bg="black", fg="#a0ff80", font=('Arial', 12), padx=10, pady=10)
list_frame.pack(fill="x", pady=10)

# Add buttons for removing password and copying hash under "List Options"
tk.Button(list_frame, text="Remove Selected Password", command=remove_password, bg="#404040", fg="white").pack(side=tk.LEFT, padx=10)
tk.Button(list_frame, text="Copy Hash", command=copy_hash, bg="#404040", fg="white").pack(side=tk.LEFT, padx=10)

# Password Entry Frame
password_frame = tk.LabelFrame(button_frame, text="Password Entry", bg="black", fg="#a0ff80", font=('Arial', 12), padx=10, pady=10)
password_frame.pack(fill="x", pady=10)

# Password entry section for manual input
tk.Label(password_frame, text="Enter Password Manually:", fg="#a0ff80", bg="black", font=('Arial', 12)).pack(side=tk.LEFT, padx=10)
password_entry = tk.Entry(password_frame, bg="#303030", fg="white", insertbackground="white")
password_entry.pack(side=tk.LEFT, padx=10)
password_entry.bind("<Return>", add_password_from_entry)  # Add on pressing Enter

# Add password button
add_button = tk.Button(password_frame, text="Add Password", command=add_password_from_entry, state=tk.DISABLED, bg="#404040", fg="white")
add_button.pack(side=tk.LEFT, padx=10)
password_entry.bind("<KeyRelease>", update_add_button_state)  # Enable/disable add button based on input

# Load passwords from a file button
tk.Button(password_frame, text="Load Passwords from File", command=load_passwords_from_file, bg="#404040", fg="white").pack(side=tk.LEFT, padx=20)

# Hashing options frame
hash_frame = tk.LabelFrame(button_frame, text="Hashing Options", bg="black", fg="#a0ff80", font=('Arial', 12), padx=10, pady=10)
hash_frame.pack(fill="x", pady=10)

# Hash function selection
hash_function_var = tk.StringVar(value="MD5")
tk.Label(hash_frame, text="Hashing Algorithm:", fg="#a0ff80", bg="black", font=('Arial', 12)).pack(side=tk.LEFT, padx=20)
hash_function_menu = ttk.Combobox(hash_frame, textvariable=hash_function_var, values=["MD5", "SHA256", "SHA512", "SHA1"])
hash_function_menu.pack(side=tk.LEFT, padx=20)
hash_function_menu.bind("<<ComboboxSelected>>", on_hash_function_change)

# Save button
tk.Button(button_frame, text="Save to File", command=save_to_file, bg="#404040", fg="white").pack(side=tk.LEFT, padx=20)

# Instructions button
tk.Button(button_frame, text="Instructions", command=show_intro, bg="#404040", fg="white").pack(side=tk.RIGHT, padx=10)

# Signature at the bottom of the window
signature = tk.Label(root, text="Created by jgpython", font=("Arial", 10, "italic"), bg="black", fg="#a0ff80")
signature.pack(side=tk.BOTTOM, pady=10)

# Start the main event loop
root.mainloop()
