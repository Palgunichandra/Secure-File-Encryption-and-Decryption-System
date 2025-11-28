import os
import base64
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


# ============================
# CRYPTO FUNCTIONS
# ============================

def derive_key(password: str, salt: bytes) -> bytes:
    """Generate a strong AES key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)


def encrypt_file(filepath: str, password: str) -> str:
    """Encrypt file using password + random salt."""
    with open(filepath, "rb") as f:
        data = f.read()

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    encrypted_data = fernet.encrypt(data)

    output_path = filepath + ".enc"

    with open(output_path, "wb") as f:
        f.write(salt + encrypted_data)

    return output_path


def decrypt_file(filepath: str, password: str) -> str:
    """Decrypt .enc file."""
    with open(filepath, "rb") as f:
        blob = f.read()

    if len(blob) < 17:
        raise ValueError("Not a valid encrypted file!")

    salt = blob[:16]
    encrypted_data = blob[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken:
        raise ValueError("Wrong password or corrupted file!")

    if filepath.endswith(".enc"):
        output_path = filepath[:-4]
    else:
        output_path = filepath + ".dec"

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    return output_path


# ============================
# GUI APPLICATION
# ============================

class EncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Encryption Tool")
        master.geometry("420x260")

        # Title
        Label(master, text="Secure File Encryption System",
              font=("Arial", 14, "bold")).pack(pady=10)

        # Password entry
        Label(master, text="Enter Password:").pack()
        self.password_entry = Entry(master, show="*")
        self.password_entry.pack(fill="x", padx=20, pady=5)

        # Buttons
        Button(master, text="View File Before Encrypting",
               command=self.view_file).pack(pady=5)

        Button(master, text="Encrypt File",
               command=self.encrypt_button_clicked).pack(pady=5)

        Button(master, text="Decrypt File",
               command=self.decrypt_button_clicked).pack(pady=5)

    # ======================
    # BUTTON FUNCTIONS
    # ======================

    def get_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Password Missing",
                                   "Please enter a password.")
            return ""
        return password

    def view_file(self):
        """Opens any document or image before encrypting."""
        filepath = filedialog.askopenfilename(title="Select file to view")

        if not filepath:
            return

        try:
            os.startfile(filepath)  # Windows default open
        except Exception:
            messagebox.showerror("Error", "Unable to open this file.")

    def encrypt_button_clicked(self):
        password = self.get_password()
        if not password:
            return

        filepath = filedialog.askopenfilename(title="Select file to encrypt")

        if not filepath:
            return

        try:
            out_path = encrypt_file(filepath, password)
            messagebox.showinfo("Success",
                                f"File Encrypted Successfully!\nSaved as:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption Failed:\n{e}")

    def decrypt_button_clicked(self):
        password = self.get_password()
        if not password:
            return

        filepath = filedialog.askopenfilename(
            title="Select file to decrypt",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )

        if not filepath:
            return

        try:
            out_path = decrypt_file(filepath, password)
            messagebox.showinfo("Success",
                                f"File Decrypted Successfully!\nSaved as:\n{out_path}\n\n(Note: File will NOT auto open)")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption Failed:\n{e}")


# ============================
# RUN APP
# ============================

if __name__ == "__main__":
    root = Tk()
    app = EncryptorApp(root)
    root.mainloop()
