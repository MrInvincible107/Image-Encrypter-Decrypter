import os
import sys
import getpass
import argparse
import secrets

# --- crypto primitives ---
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

HEADER = b'ENCIMG1'
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200_000

def derive_key(password: bytes, salt: bytes, length: int = 32, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def encrypt_file(in_path: str, out_path: str, password: str, iterations: int = KDF_ITERATIONS) -> None:
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password.encode('utf-8'), salt, iterations=iterations)
    aesgcm = AESGCM(key)
    with open(in_path, 'rb') as f:
        pt = f.read()
    ct = aesgcm.encrypt(nonce, pt, None)
    with open(out_path, 'wb') as f:
        f.write(HEADER + salt + nonce + ct)

def decrypt_file(in_path: str, out_path: str, password: str, iterations: int = KDF_ITERATIONS) -> None:
    with open(in_path, 'rb') as f:
        blob = f.read()
    if not blob.startswith(HEADER):
        raise ValueError("Input file is not in expected encrypted format (bad header)")
    off = len(HEADER)
    salt = blob[off:off+SALT_SIZE]; off += SALT_SIZE
    nonce = blob[off:off+NONCE_SIZE]; off += NONCE_SIZE
    ct = blob[off:]
    key = derive_key(password.encode('utf-8'), salt, iterations=iterations)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    with open(out_path, 'wb') as f:
        f.write(pt)

# --- Tkinter helpers ---
def choose_open_file(title: str, filetypes):
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)   # 👈 makes the dialog appear on top
        root.update()
        path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        root.update()
        root.destroy()
        if path:
            return path
        print("No file selected. You can paste a path instead (or press Enter to cancel).")
    except Exception:
        print("GUI file picker not available. Falling back to console.")
    path = input("Enter full path to the file (blank to cancel): ").strip('"').strip()
    return path or None


def choose_save_file(title: str, defaultextension: str, initialfile: str = ""):
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)   # 👈 same trick here
        root.update()
        path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=defaultextension,
            initialfile=initialfile,
        )
        root.update()
        root.destroy()
        if path:
            return path
        print("No output chosen. You can paste a path instead (or press Enter to cancel).")
    except Exception:
        print("GUI save dialog not available. Falling back to console.")
    path = input("Enter full output path (blank to cancel): ").strip('"').strip()
    return path or None


def prompt_password(need_confirm: bool) -> str | None:
    """
    Show a GUI password prompt (with optional confirmation).
    Falls back to console if Tk isn't available.
    Returns the password string, or None if cancelled/mismatch.
    """
    try:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        pwd = simpledialog.askstring("Password", "Enter password:", show="*", parent=root)
        if pwd is None or pwd == "":
            root.destroy()
            return None
        if need_confirm:
            pwd2 = simpledialog.askstring("Confirm Password", "Confirm password:", show="*", parent=root)
            if pwd2 is None or pwd != pwd2:
                messagebox.showerror("Password", "Passwords do not match.")
                root.destroy()
                return None
        root.destroy()
        return pwd
    except Exception:
        # Console fallback
        import getpass
        pwd = getpass.getpass("Enter password: ")
        if not pwd:
            return None
        if need_confirm:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd != pwd2:
                print("Passwords do not match.")
                return None
        return pwd

def interactive_menu(iterations: int = KDF_ITERATIONS):
    print("="*50)
    print(" Image/File Encrypter (AES-GCM, PBKDF2)")
    print("="*50)
    print("1) Encrypt a file (pick via dialog)")
    print("2) Decrypt a file (pick via dialog)")
    print("3) Exit")
    choice = input("Select an option: ").strip()

    if choice == "1":
        in_path = choose_open_file("Select file to encrypt", [
            ("Images", "*.jpg *.jpeg *.png *.gif *.bmp *.tiff *.webp"),
            ("All Files", "*.*"),
        ])
        if not in_path:
            print("No file selected.")
            return
        default_out = os.path.basename(in_path) + ".enc"
        out_path = choose_save_file("Save encrypted file as", ".enc", default_out)
        if not out_path:
            print("No output selected.")
            return
        pwd = prompt_password(need_confirm=True)
        if not pwd:
            print("Encryption cancelled (no password).")
            return
        try:
            encrypt_file(in_path, out_path, pwd, iterations)
            print(f"✅ Encrypted:\n  {in_path}\n→ {out_path}")
        except Exception as e:
            print(f"❌ Encryption error: {e}")


    elif choice == "2":
        in_path = choose_open_file("Select encrypted file (.enc)", [
            ("Encrypted", "*.enc"),
            ("All Files", "*.*"),
        ])
        if not in_path:
            print("No file selected.")
            return
        # Try to guess original name (strip .enc)
        base = os.path.basename(in_path)
        guessed = base[:-4] if base.endswith(".enc") else f"decrypted_{base}"
        out_path = choose_save_file("Save decrypted file as", "", guessed)
        if not out_path:
            print("No output selected.")
            return
        pwd = prompt_password(need_confirm=False)
        if not pwd:
            print("Decryption cancelled (no password).")
            return
        try:
            decrypt_file(in_path, out_path, pwd, iterations)
            print(f"✅ Decrypted:\n  {in_path}\n→ {out_path}")
        except InvalidTag:
            print("❌ Authentication failed: wrong password or file was tampered.")
        except Exception as e:
            print(f"❌ Decryption error: {e}")


    elif choice == "3":
        print("Bye!")
    else:
        print("Unknown option.")

# --- CLI wrapper (keeps prior behavior) ---
def main():
    parser = argparse.ArgumentParser(
        description="Encrypt/decrypt images (or any files) using AES-GCM + PBKDF2.\n"
                    "Run with no subcommand to use the interactive menu + file picker."
    )
    parser.add_argument("--kdf-iters", type=int, default=KDF_ITERATIONS,
                        help=f"PBKDF2 iterations (default {KDF_ITERATIONS})")
    sub = parser.add_subparsers(dest="command")

    enc = sub.add_parser("encrypt", help="Encrypt a file (non-interactive)")
    enc.add_argument("input")
    enc.add_argument("output")

    dec = sub.add_parser("decrypt", help="Decrypt a file (non-interactive)")
    dec.add_argument("input")
    dec.add_argument("output")

    args = parser.parse_args()

    if not args.command:
        # Interactive mode
        interactive_menu(iterations=args.kdf_iters)
        return

    # Non-interactive CLI mode (compatible with your old commands)
    pwd = getpass.getpass("Enter password: ")
    if not pwd:
        print("Empty password not allowed.", file=sys.stderr)
        sys.exit(2)

    if args.command == "encrypt":
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(2)
        try:
            encrypt_file(args.input, args.output, pwd, args.kdf_iters)
            print(f"Encrypted {args.input} -> {args.output}")
        except Exception as e:
            print("Encryption error:", e, file=sys.stderr)
            sys.exit(1)

    elif args.command == "decrypt":
        try:
            decrypt_file(args.input, args.output, pwd, args.kdf_iters)
            print(f"Decrypted {args.input} -> {args.output}")
        except InvalidTag:
            print("Decryption failed: wrong password or tampered file.", file=sys.stderr)
            sys.exit(3)
        except Exception as e:
            print("Decryption error:", e, file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
