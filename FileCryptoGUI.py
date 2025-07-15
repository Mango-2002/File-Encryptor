import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import traceback

# -------- Core Logic -------- #
def generate_key():
    # 32 bytes = 256-bit AES key
    return get_random_bytes(32)

def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        enc_file = file_path + ".enc"
        with open(enc_file, 'wb') as f:
            # Save nonce, tag, and ciphertext
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)

        return enc_file
    except Exception as e:
        traceback.print_exc()
        raise RuntimeError("Encryption failed!") from e

def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        # Remove .enc if present
        if file_path.endswith(".enc"):
            dec_file = file_path[:-4]
        else:
            dec_file = file_path + ".dec"

        with open(dec_file, 'wb') as f:
            f.write(data)

        return dec_file
    except Exception as e:
        traceback.print_exc()
        raise RuntimeError("Decryption failed! (Wrong key or corrupted file)") from e

# -------- GUI Logic -------- #
def browse_file():
    path = filedialog.askopenfilename()
    if path:
        file_path_var.set(path)

def do_encrypt():
    file_path = file_path_var.get().strip()
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file.")
        return
    try:
        key = generate_key()
        output_file = encrypt_file(file_path, key)
        # Clear previous and show key
        key_display.delete(1.0, tk.END)
        key_display.insert(tk.END, f"{key.hex()}")
        messagebox.showinfo("Success", f"Encrypted file saved as:\n{output_file}\n\nKey displayed below.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_decrypt():
    file_path = file_path_var.get().strip()
    key_hex = key_entry.get().strip()
    if not file_path or not key_hex:
        messagebox.showwarning("Warning", "Please select a file and enter a key.")
        return
    try:
        key = bytes.fromhex(key_hex)
        output_file = decrypt_file(file_path, key)
        messagebox.showinfo("Success", f"Decrypted file saved as:\n{output_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_key():
    # Copy displayed key to clipboard
    key_text = key_display.get(1.0, tk.END).strip()
    if key_text:
        root.clipboard_clear()
        root.clipboard_append(key_text)
        root.update()
        messagebox.showinfo("Copied", "Key copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No key to copy!")

# -------- GUI Setup -------- #
root = tk.Tk()
root.title("File Encryption & Decryption Tool")
root.geometry("500x400")
root.resizable(False, False)

file_path_var = tk.StringVar()

tk.Label(root, text="Select File:", font=("Arial", 12)).pack(pady=5)
tk.Entry(root, textvariable=file_path_var, width=50, font=("Arial", 10)).pack(pady=2)
tk.Button(root, text="Browse", command=browse_file, bg="#007acc", fg="white").pack(pady=5)

tk.Label(root, text="Key (for Decryption):", font=("Arial", 12)).pack(pady=5)
key_entry = tk.Entry(root, width=60, font=("Arial", 10))
key_entry.pack(pady=2)

tk.Button(root, text="Encrypt File", command=do_encrypt, bg="green", fg="white", width=15).pack(pady=10)
tk.Button(root, text="Decrypt File", command=do_decrypt, bg="orange", fg="white", width=15).pack(pady=5)

# Key display area
tk.Label(root, text="Generated AES Key (copy and save):", font=("Arial", 12)).pack(pady=5)
key_display = tk.Text(root, height=3, width=60, wrap="word")
key_display.pack(pady=2)

tk.Button(root, text="Copy Key to Clipboard", command=copy_key, bg="#555", fg="white").pack(pady=5)

root.mainloop()
