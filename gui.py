import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Try to reuse existing app logic; fall back to a helpful error if missing
MISSING_MODULES = False
try:
    from modules.hash import hash_file, verify_integrity
    from modules.encryption import aes_ed, rsa_ed
    from modules.password import check_strength, hash_pw, verify_password
except Exception:  # ImportError or other import-time errors
    MISSING_MODULES = True
    def _missing(*args, **kwargs):  # type: ignore
        raise RuntimeError(
            "Required 'modules' package not found. Please add the 'modules' folder "
            "containing hash.py, encryption.py, and password.py next to gui.py/main.py, "
            "or fix PYTHONPATH so 'from modules ...' works."
        )
    hash_file = _missing
    verify_integrity = _missing
    aes_ed = _missing
    rsa_ed = _missing
    check_strength = _missing
    hash_pw = _missing
    verify_password = _missing


class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cryptography Toolkit v1.0 — GUI")
        self.geometry("820x560")
        self.minsize(760, 520)

        self._hashed_password = None

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.hash_tab = ttk.Frame(notebook)
        self.integrity_tab = ttk.Frame(notebook)
        self.aes_tab = ttk.Frame(notebook)
        self.rsa_tab = ttk.Frame(notebook)
        self.password_tab = ttk.Frame(notebook)

        notebook.add(self.hash_tab, text="Hash File")
        notebook.add(self.integrity_tab, text="Check Integrity")
        notebook.add(self.aes_tab, text="AES")
        notebook.add(self.rsa_tab, text="RSA")
        notebook.add(self.password_tab, text="Password Manager")

        self._build_hash_tab()
        self._build_integrity_tab()
        self._build_aes_tab()
        self._build_rsa_tab()
        self._build_password_tab()

    # ---------- Shared helpers ----------
    def _browse_for_file(self, entry: ttk.Entry, title: str = "Select file"):
        path = filedialog.askopenfilename(title=title)
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def _set_text(self, widget: tk.Text, text: str):
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.configure(state=tk.DISABLED)

    # ---------- Hash tab ----------
    def _build_hash_tab(self):
        frm = ttk.Frame(self.hash_tab, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        path_lbl = ttk.Label(frm, text="File path:")
        path_lbl.grid(row=0, column=0, sticky="w")

        self.hash_path = ttk.Entry(frm, width=70)
        self.hash_path.grid(row=1, column=0, sticky="we", padx=(0, 8))

        browse_btn = ttk.Button(frm, text="Browse", command=lambda: self._browse_for_file(self.hash_path))
        browse_btn.grid(row=1, column=1, sticky="w")

        run_btn = ttk.Button(frm, text="Compute SHA Hash", command=self._do_hash)
        run_btn.grid(row=2, column=0, pady=(10, 8), sticky="w")

        out_lbl = ttk.Label(frm, text="Result:")
        out_lbl.grid(row=3, column=0, sticky="w")

        self.hash_out = tk.Text(frm, height=6, wrap=tk.WORD)
        self.hash_out.grid(row=4, column=0, columnspan=2, sticky="nsew")

        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(4, weight=1)

    def _do_hash(self):
        path = self.hash_path.get().strip()
        if not path:
            messagebox.showwarning("Missing file", "Please choose a file to hash.")
            return
        try:
            digest = hash_file(path)
            self._set_text(self.hash_out, f"SHA hash for:\n{path}\n\n{digest}")
        except Exception as e:
            messagebox.showerror("Hash failed", str(e))

    # ---------- Integrity tab ----------
    def _build_integrity_tab(self):
        frm = ttk.Frame(self.integrity_tab, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="File path 1:").grid(row=0, column=0, sticky="w")
        self.int_path1 = ttk.Entry(frm, width=70)
        self.int_path1.grid(row=1, column=0, sticky="we", padx=(0, 8))
        ttk.Button(frm, text="Browse", command=lambda: self._browse_for_file(self.int_path1, "Select first file")).grid(row=1, column=1)

        ttk.Label(frm, text="File path 2:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.int_path2 = ttk.Entry(frm, width=70)
        self.int_path2.grid(row=3, column=0, sticky="we", padx=(0, 8))
        ttk.Button(frm, text="Browse", command=lambda: self._browse_for_file(self.int_path2, "Select second file")).grid(row=3, column=1)

        ttk.Button(frm, text="Compare Integrity", command=self._do_integrity).grid(row=4, column=0, pady=(10, 8), sticky="w")

        ttk.Label(frm, text="Result:").grid(row=5, column=0, sticky="w")
        self.int_out = tk.Text(frm, height=6, wrap=tk.WORD)
        self.int_out.grid(row=6, column=0, columnspan=2, sticky="nsew")

        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(6, weight=1)

    def _do_integrity(self):
        p1 = self.int_path1.get().strip()
        p2 = self.int_path2.get().strip()
        if not p1 or not p2:
            messagebox.showwarning("Missing files", "Please choose two files to compare.")
            return
        try:
            result = verify_integrity(p1, p2)
            self._set_text(self.int_out, str(result))
        except Exception as e:
            messagebox.showerror("Integrity check failed", str(e))

    # ---------- AES tab ----------
    def _build_aes_tab(self):
        frm = ttk.Frame(self.aes_tab, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Message:").grid(row=0, column=0, sticky="w")
        self.aes_msg = tk.Text(frm, height=4, wrap=tk.WORD)
        self.aes_msg.grid(row=1, column=0, columnspan=2, sticky="nsew")

        ttk.Button(frm, text="Encrypt / Decrypt", command=self._do_aes).grid(row=2, column=0, pady=(10, 8), sticky="w")

        ttk.Label(frm, text="Output:").grid(row=3, column=0, sticky="w")
        self.aes_out = tk.Text(frm, height=10, wrap=tk.WORD)
        self.aes_out.grid(row=4, column=0, columnspan=2, sticky="nsew")

        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)
        frm.rowconfigure(4, weight=1)

    def _do_aes(self):
        msg = self.aes_msg.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("Missing message", "Please enter a message to encrypt.")
            return
        try:
            key, ciphertext, plaintext = aes_ed(msg)
            out = (
                "AES Result\n"
                "-------------\n"
                f"Key: {key}\n\n"
                f"Ciphertext: {ciphertext}\n\n"
                f"Plaintext: {plaintext}\n"
            )
            self._set_text(self.aes_out, out)
        except Exception as e:
            messagebox.showerror("AES operation failed", str(e))

    # ---------- RSA tab ----------
    def _build_rsa_tab(self):
        frm = ttk.Frame(self.rsa_tab, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Message:").grid(row=0, column=0, sticky="w")
        self.rsa_msg = tk.Text(frm, height=4, wrap=tk.WORD)
        self.rsa_msg.grid(row=1, column=0, columnspan=2, sticky="nsew")

        ttk.Button(frm, text="Encrypt / Decrypt", command=self._do_rsa).grid(row=2, column=0, pady=(10, 8), sticky="w")

        ttk.Label(frm, text="Output:").grid(row=3, column=0, sticky="w")
        self.rsa_out = tk.Text(frm, height=10, wrap=tk.WORD)
        self.rsa_out.grid(row=4, column=0, columnspan=2, sticky="nsew")

        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)
        frm.rowconfigure(4, weight=1)

    def _do_rsa(self):
        msg = self.rsa_msg.get("1.0", tk.END).strip()
        if not msg:
            messagebox.showwarning("Missing message", "Please enter a message to encrypt.")
            return
        try:
            ciphertext, plaintext = rsa_ed(msg)
            out = (
                "RSA Result\n"
                "-----------\n"
                f"Ciphertext: {ciphertext}\n\n"
                f"Plaintext: {plaintext}\n"
            )
            self._set_text(self.rsa_out, out)
        except Exception as e:
            messagebox.showerror("RSA operation failed", str(e))

    # ---------- Password tab ----------
    def _build_password_tab(self):
        frm = ttk.Frame(self.password_tab, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Enter password:").grid(row=0, column=0, sticky="w")
        self.pw_entry = ttk.Entry(frm, show="*")
        self.pw_entry.grid(row=1, column=0, sticky="we", padx=(0, 8))

        ttk.Button(frm, text="Check Strength", command=self._check_strength).grid(row=1, column=1, sticky="w")

        self.pw_strength_lbl = ttk.Label(frm, text="Strength: —")
        self.pw_strength_lbl.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 4))

        ttk.Separator(frm).grid(row=3, column=0, columnspan=2, sticky="we", pady=8)

        ttk.Label(frm, text="Hash & Verify:").grid(row=4, column=0, sticky="w")
        ttk.Button(frm, text="Hash Password", command=self._hash_password).grid(row=5, column=0, sticky="w")

        ttk.Label(frm, text="Re-enter to verify:").grid(row=6, column=0, sticky="w", pady=(8, 0))
        self.pw_verify_entry = ttk.Entry(frm, show="*")
        self.pw_verify_entry.grid(row=7, column=0, sticky="we", padx=(0, 8))
        ttk.Button(frm, text="Verify", command=self._verify_password).grid(row=7, column=1, sticky="w")

        ttk.Label(frm, text="Output:").grid(row=8, column=0, sticky="w", pady=(10, 0))
        self.pw_out = tk.Text(frm, height=8, wrap=tk.WORD)
        self.pw_out.grid(row=9, column=0, columnspan=2, sticky="nsew")

        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(9, weight=1)

    def _check_strength(self):
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showwarning("Missing password", "Please enter a password to check.")
            return
        try:
            result = check_strength(pw)
            self.pw_strength_lbl.configure(text=f"Strength: {result}")
            if str(result).lower().startswith("weak"):
                messagebox.showinfo("Weak password", "Please choose a stronger password.")
        except Exception as e:
            messagebox.showerror("Strength check failed", str(e))

    def _hash_password(self):
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showwarning("Missing password", "Please enter a password to hash.")
            return
        try:
            self._hashed_password = hash_pw(pw)
            self._set_text(self.pw_out, f"Hashed password (stored in-memory):\n{self._hashed_password}")
        except Exception as e:
            messagebox.showerror("Hash failed", str(e))

    def _verify_password(self):
        if not self._hashed_password:
            messagebox.showwarning("No hash", "Please hash a password first.")
            return
        attempt = self.pw_verify_entry.get()
        try:
            verdict = verify_password(attempt, self._hashed_password)
            self._set_text(self.pw_out, f"Verification result: {verdict}\n\nStored hash:\n{self._hashed_password}")
        except Exception as e:
            messagebox.showerror("Verify failed", str(e))


if __name__ == "__main__":
    if MISSING_MODULES:
        # Show a clear error and exit gracefully
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Missing project modules",
            "The 'modules' package is not available.\n\n"
            "Make sure a folder named 'modules' exists next to gui.py/main.py, "
            "and it contains:\n"
            "  - hash.py (with hash_file, verify_integrity)\n"
            "  - encryption.py (with aes_ed, rsa_ed)\n"
            "  - password.py (with check_strength, hash_pw, verify_password)\n\n"
            "Alternatively, adjust PYTHONPATH so that 'from modules ...' resolves."
        )
        root.destroy()
    else:
        app = CryptoApp()
        app.mainloop()
