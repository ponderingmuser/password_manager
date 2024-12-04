from tkinter import *
from tkinter import messagebox
import random
import pyperclip
from cryptography.fernet import Fernet
import os
import bcrypt

#Encryption
KEY_FILE = "encryption_key.key"
PASSWORD_FILE = "password_data.txt"
HASH_FILE= "master_password.hash"

# Load or create the encryption key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
        return key

key = load_or_create_key()
cipher = Fernet(key)
# ---------------------------- PASSWORD GENERATOR ------------------------------- #
#Password Generator Project
def generate_password():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    password_letters = [random.choice(letters) for letter in range(random.randint(8, 10))]
    password_numbers = [random.choice(numbers) for number in range(random.randint(2, 4))]
    password_symbols = [random.choice(symbols) for symbol in range(random.randint(2, 4))]

    password_list = password_symbols + password_numbers + password_letters
    random.shuffle(password_list)

    password = "".join(password_list)
    password_entry.insert(0, password)
    pyperclip.copy(password)

# ---------------------------- SAVE PASSWORD ------------------------------- #
def add_password():
    site = website_entry.get()
    user = email_entry.get()
    pw = password_entry.get()

    if len(site) == 0 or len(pw) == 0:
        messagebox.showerror(title="Oops!", message="Don't leave any fields empty!")
    else:
        is_ok = messagebox.askokcancel(title=site, message=f"These are what you entered: \n"
                                                           f"Email/Username: {user} \nPassword: {pw}\n"
                                                           f"Is it ok to save?")
        if is_ok:
            encrypted_data = cipher.encrypt(f"{site} | {user} | {pw}".encode())  # No newline here
            with open("password_data.txt", "ab") as file:
                file.write(encrypted_data + b"\n")  # Add newline for separation
            website_entry.delete(0, END)
            password_entry.delete(0, END)


# -------------------------VIEW PASSWORD LIST--------------------------- #
def show_passwords():
    # Check if the hash file exists
    if not os.path.exists(HASH_FILE):
        prompt_to_create_master_password()

    def authenticate():
        entered_password = master_password_entry.get()
        if verify_master_password(entered_password):
            top.destroy()
            open_passwords_window()
        else:
            messagebox.showerror("Error", "Incorrect Master Password!")

    def open_passwords_window():
        passwords_window = Toplevel(window)
        passwords_window.title("Stored Passwords")
        passwords_window.geometry("600x400")

        try:
            with open(PASSWORD_FILE, "rb") as file:
                encrypted_lines = file.readlines()
                decrypted_lines = [
                    cipher.decrypt(line.strip()).decode() for line in encrypted_lines if line.strip()
                ]

            # Display decrypted passwords
            text_widget = Text(passwords_window, wrap=WORD)
            text_widget.insert("1.0", "\n".join(decrypted_lines))
            text_widget.config(state="disabled")
            text_widget.pack(padx=10, pady=10, fill=BOTH, expand=True)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read passwords: {e}")

    # Prompt for master password
    top = Toplevel(window)
    top.title("Enter Master Password")
    Label(top, text="Master Password:").pack(pady=5)
    master_password_entry = Entry(top, show="*", width=20)
    master_password_entry.pack(pady=5)
    Button(top, text="Submit", command=authenticate).pack(pady=10)

# Function to prompt user to create a master password
def prompt_to_create_master_password():
    def save_master_password():
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        if os.path.exists(PASSWORD_FILE):
            confirm = messagebox.askyesno(
                "Warning",
                "Resetting the master password will erase all stored passwords. Do you want to proceed?"
            )
            if not confirm:
                return
            # Erase the password file
            os.remove(PASSWORD_FILE)
            messagebox.showinfo("Reset Complete", "Stored passwords have been erased.")

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        with open(HASH_FILE, "wb") as file:
            file.write(hashed_password)
        messagebox.showinfo("Success", "Master password set successfully!")
        setup_window.destroy()

    setup_window = Toplevel(window)
    setup_window.title("Set Master Password")

    Label(setup_window, text="Enter Master Password:").pack(pady=5)
    password_entry = Entry(setup_window, show="*", width=20)
    password_entry.pack(pady=5)

    Label(setup_window, text="Confirm Master Password:").pack(pady=5)
    confirm_password_entry = Entry(setup_window, show="*", width=20)
    confirm_password_entry.pack(pady=5)

    Button(setup_window, text="Save Password", command=save_master_password).pack(pady=10)

# Function to verify the master password
def verify_master_password(entered_password):
    try:
        with open(HASH_FILE, "rb") as file:
            stored_hash = file.read()
        return bcrypt.checkpw(entered_password.encode(), stored_hash)
    except Exception as e:
        messagebox.showerror("Error", f"Verification failed: {e}")
        return False



# ---------------------------- UI SETUP ------------------------------- #
window = Tk()
window.title("Password Manager")
window.config(padx=50, pady=50)


#image
canvas=Canvas(height=200, width=200)
lock_img=PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=lock_img)
canvas.grid(row=0, column=1)

#labels
website=Label(text="Website:")
website.grid(row=1, column=0, sticky="e")
email=Label(text="Email/Username:")
email.grid(row=2, column=0, sticky="e")
password=Label(text="Password:")
password.grid(row=3, column=0, sticky="e")

#inputs
website_entry=Entry(width=52)
website_entry.grid(row=1, column=1, columnspan=2, sticky="w")
email_entry=Entry(width=52)
email_entry.grid(row=2, column=1, columnspan=2, sticky="w")
password_entry=Entry(width=33)
password_entry.grid(row=3, column=1, sticky="w")

#buttons
generate=Button(text="Generate Password", command=generate_password)
generate.grid(row=3, column=2, sticky="w")
add=Button(text="Add Password", width=44, command=add_password)
add.grid(row=4, column=1, columnspan=2, sticky="w")
Button(text="See Stored Passwords", width=44, command=show_passwords).grid(row=5, column=1, columnspan=2, sticky="w")




window.mainloop()
