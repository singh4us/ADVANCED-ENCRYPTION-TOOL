from __future__ import annotations

import os
import struct
import threading
from pathlib import Path
from tkinter import StringVar, Tk, filedialog, messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"AET1"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
CHUNK_SIZE = 64 * 1024
PBKDF2_ITERATIONS = 600_000
HEADER_STRUCT = struct.Struct(">4sBI16s12s")


class EncryptionError(Exception):
    """Raised when a file cannot be encrypted or decrypted safely."""


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def build_output_path(input_path: Path, operation: str) -> Path:
    if operation == "encrypt":
        return input_path.with_suffix(input_path.suffix + ".aes")

    if input_path.suffix == ".aes":
        return input_path.with_suffix("")

    return input_path.with_name(f"{input_path.stem}_decrypted{input_path.suffix}")


def encrypt_file(source: Path, destination: Path, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()

    try:
        with source.open("rb") as infile, destination.open("wb") as outfile:
            header = HEADER_STRUCT.pack(MAGIC, VERSION, PBKDF2_ITERATIONS, salt, nonce)
            outfile.write(header)

            while chunk := infile.read(CHUNK_SIZE):
                outfile.write(encryptor.update(chunk))

            outfile.write(encryptor.finalize())
            outfile.write(encryptor.tag)
    except Exception as exc:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise EncryptionError(f"Encryption failed: {exc}") from exc


def decrypt_file(source: Path, destination: Path, password: str) -> None:
    try:
        file_size = source.stat().st_size
        minimum_size = HEADER_STRUCT.size + TAG_SIZE
        if file_size < minimum_size:
            raise EncryptionError("The selected file is too small to be a valid encrypted file.")

        with source.open("rb") as infile:
            header_bytes = infile.read(HEADER_STRUCT.size)
            magic, version, iterations, salt, nonce = HEADER_STRUCT.unpack(header_bytes)

            if magic != MAGIC:
                raise EncryptionError("Unsupported file format. Choose a file created by this app.")
            if version != VERSION:
                raise EncryptionError("Unsupported encrypted file version.")
            if iterations != PBKDF2_ITERATIONS:
                raise EncryptionError("Unsupported key derivation settings in the encrypted file.")

            tag_position = file_size - TAG_SIZE
            infile.seek(tag_position)
            tag = infile.read(TAG_SIZE)
            infile.seek(HEADER_STRUCT.size)

            key = derive_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            remaining = tag_position - HEADER_STRUCT.size

            with destination.open("wb") as outfile:
                while remaining > 0:
                    chunk = infile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    outfile.write(decryptor.update(chunk))

                outfile.write(decryptor.finalize())
    except InvalidTag as exc:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise EncryptionError("Decryption failed. The password is incorrect or the file was modified.") from exc
    except EncryptionError:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise
    except Exception as exc:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise EncryptionError(f"Decryption failed: {exc}") from exc


class EncryptionApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("Advanced Encryption Tool")
        self.root.geometry("640x380")
        self.root.minsize(620, 360)

        self.mode_var = StringVar(value="encrypt")
        self.file_var = StringVar()
        self.output_var = StringVar()
        self.password_var = StringVar()
        self.confirm_var = StringVar()
        self.status_var = StringVar(value="Choose a file to begin.")

        self._build_ui()
        self._sync_output_path()

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=20)
        main.grid(sticky="nsew")
        main.columnconfigure(1, weight=1)

        title = ttk.Label(main, text="AES-256 File Encryption", font=("Segoe UI", 18, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w")

        subtitle = ttk.Label(
            main,
            text="Encrypt and decrypt files with AES-256-GCM and password-based protection.",
        )
        subtitle.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 18))

        ttk.Label(main, text="Mode").grid(row=2, column=0, sticky="w", pady=6)
        mode_frame = ttk.Frame(main)
        mode_frame.grid(row=2, column=1, columnspan=2, sticky="w")
        ttk.Radiobutton(
            mode_frame,
            text="Encrypt",
            value="encrypt",
            variable=self.mode_var,
            command=self._on_mode_change,
        ).grid(row=0, column=0, padx=(0, 12))
        ttk.Radiobutton(
            mode_frame,
            text="Decrypt",
            value="decrypt",
            variable=self.mode_var,
            command=self._on_mode_change,
        ).grid(row=0, column=1)

        ttk.Label(main, text="Input file").grid(row=3, column=0, sticky="w", pady=6)
        ttk.Entry(main, textvariable=self.file_var).grid(row=3, column=1, sticky="ew", pady=6)
        ttk.Button(main, text="Browse", command=self._choose_input_file).grid(row=3, column=2, padx=(10, 0))

        ttk.Label(main, text="Output file").grid(row=4, column=0, sticky="w", pady=6)
        ttk.Entry(main, textvariable=self.output_var).grid(row=4, column=1, sticky="ew", pady=6)
        ttk.Button(main, text="Save As", command=self._choose_output_file).grid(row=4, column=2, padx=(10, 0))

        ttk.Label(main, text="Password").grid(row=5, column=0, sticky="w", pady=6)
        ttk.Entry(main, textvariable=self.password_var, show="*").grid(row=5, column=1, sticky="ew", pady=6)

        ttk.Label(main, text="Confirm password").grid(row=6, column=0, sticky="w", pady=6)
        ttk.Entry(main, textvariable=self.confirm_var, show="*").grid(row=6, column=1, sticky="ew", pady=6)

        note = ttk.Label(
            main,
            text="Tip: keep your password safe. Lost passwords cannot be recovered.",
            foreground="#555555",
        )
        note.grid(row=7, column=0, columnspan=3, sticky="w", pady=(10, 14))

        self.action_button = ttk.Button(main, text="Encrypt File", command=self._start_processing)
        self.action_button.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(0, 12))

        status_frame = ttk.LabelFrame(main, text="Status", padding=12)
        status_frame.grid(row=9, column=0, columnspan=3, sticky="nsew")
        status_frame.columnconfigure(0, weight=1)
        main.rowconfigure(9, weight=1)
        ttk.Label(status_frame, textvariable=self.status_var, wraplength=560, justify="left").grid(sticky="w")

    def _on_mode_change(self) -> None:
        is_encrypt = self.mode_var.get() == "encrypt"
        self.action_button.config(text="Encrypt File" if is_encrypt else "Decrypt File")
        self.confirm_var.set("")
        self._sync_output_path()
        self.status_var.set(
            "Choose a file to encrypt securely."
            if is_encrypt
            else "Choose an encrypted .aes file and enter the password to decrypt it."
        )

    def _choose_input_file(self) -> None:
        filetypes = [("Encrypted files", "*.aes"), ("All files", "*.*")]
        selected = filedialog.askopenfilename(
            title="Select a file",
            filetypes=filetypes if self.mode_var.get() == "decrypt" else [("All files", "*.*")],
        )
        if selected:
            self.file_var.set(selected)
            self._sync_output_path()

    def _choose_output_file(self) -> None:
        operation = self.mode_var.get()
        default_name = ""
        if self.file_var.get():
            default_name = build_output_path(Path(self.file_var.get()), operation).name

        selected = filedialog.asksaveasfilename(
            title="Choose where to save the result",
            initialfile=default_name,
            defaultextension=".aes" if operation == "encrypt" else "",
            filetypes=[("Encrypted files", "*.aes"), ("All files", "*.*")],
        )
        if selected:
            self.output_var.set(selected)

    def _sync_output_path(self) -> None:
        file_path = self.file_var.get().strip()
        if not file_path:
            self.output_var.set("")
            return

        generated = build_output_path(Path(file_path), self.mode_var.get())
        self.output_var.set(str(generated))

    def _validate_inputs(self) -> tuple[Path, Path, str]:
        source_text = self.file_var.get().strip()
        destination_text = self.output_var.get().strip()
        password = self.password_var.get()
        confirmation = self.confirm_var.get()

        if not source_text:
            raise EncryptionError("Please choose an input file.")
        if not destination_text:
            raise EncryptionError("Please choose where to save the result.")
        if not password:
            raise EncryptionError("Please enter a password.")
        if len(password) < 8:
            raise EncryptionError("Use a password with at least 8 characters.")
        if password != confirmation:
            raise EncryptionError("The password and confirmation do not match.")

        source = Path(source_text)
        destination = Path(destination_text)

        if not source.exists() or not source.is_file():
            raise EncryptionError("The selected input file does not exist.")
        if source.resolve() == destination.resolve():
            raise EncryptionError("Choose a different output file so the source is not overwritten.")

        if destination.exists():
            overwrite = messagebox.askyesno(
                "Overwrite file?",
                f"{destination.name} already exists. Do you want to replace it?",
            )
            if not overwrite:
                raise EncryptionError("Operation cancelled. Choose a different output file.")

        return source, destination, password

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.action_button.config(state=state)

    def _start_processing(self) -> None:
        try:
            source, destination, password = self._validate_inputs()
        except EncryptionError as exc:
            self.status_var.set(str(exc))
            return

        self._set_busy(True)
        operation = self.mode_var.get()
        self.status_var.set(f"{operation.capitalize()}ion in progress. Please wait...")

        worker = threading.Thread(
            target=self._process_file,
            args=(operation, source, destination, password),
            daemon=True,
        )
        worker.start()

    def _process_file(self, operation: str, source: Path, destination: Path, password: str) -> None:
        try:
            if operation == "encrypt":
                encrypt_file(source, destination, password)
                message = f"Encryption complete. Saved to {destination}"
            else:
                decrypt_file(source, destination, password)
                message = f"Decryption complete. Saved to {destination}"
            self.root.after(0, lambda: self._finish_success(message))
        except EncryptionError as exc:
            self.root.after(0, lambda: self._finish_error(str(exc)))

    def _finish_success(self, message: str) -> None:
        self._set_busy(False)
        self.status_var.set(message)
        messagebox.showinfo("Success", message)

    def _finish_error(self, message: str) -> None:
        self._set_busy(False)
        self.status_var.set(message)
        messagebox.showerror("Operation failed", message)


def main() -> None:
    root = Tk()
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
