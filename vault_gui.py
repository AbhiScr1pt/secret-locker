#!/usr/bin/env python3
"""
Secret Locker - GUI version (fully encrypted single file)
--------------------------------------------------------------
Requires vault.py in the same folder. Everything - emails, sender
credentials, and your files - is encrypted inside myvault.dat.

Run:
    python vault_gui.py
"""

import os
import base64
import hashlib
import threading
import time
import tkinter as tk
from tkinter import messagebox

import vault


class VaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secret Locker")
        self.geometry("420x340")
        self.resizable(False, False)

        self.current_key = None
        self.pending_otp = None
        self.pending_expiry = 0
        self.pending_attempts = 3
        self.pending_purpose = None
        self.pending_new_pw = None
        self.store = None
        self.meta_dict = None  # decrypted {email, recovery_email, smtp}

        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True, padx=20, pady=20)

        self.build_initial_screen()

    def clear(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def build_initial_screen(self):
        self.clear()
        store = vault._load_store()
        if store is None:
            self.build_setup_screen()
        else:
            self.store = store
            self.build_login_screen(store)

    # ---------- first-time setup ----------

    def build_setup_screen(self):
        self.clear()
        tk.Label(self.container, text="First-Time Vault Setup", font=("Segoe UI", 14, "bold")).pack(pady=(0, 10))

        fields = {}

        def add_field(label, show=None):
            tk.Label(self.container, text=label, anchor="w").pack(fill="x")
            e = tk.Entry(self.container, show=show)
            e.pack(fill="x", pady=(0, 6))
            fields[label] = e

        add_field("Vault password", show="*")
        add_field("Confirm password", show="*")
        add_field("Primary email (gets OTP codes)")
        add_field("Recovery email (different, for password resets)")

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def do_setup():
            pw1 = fields["Vault password"].get()
            pw2 = fields["Confirm password"].get()
            email = fields["Primary email (gets OTP codes)"].get().strip()
            recovery = fields["Recovery email (different, for password resets)"].get().strip()

            if len(pw1) < 8:
                status.config(text="Password must be at least 8 characters.")
                return
            if pw1 != pw2:
                status.config(text="Passwords don't match.")
                return
            if not email or not recovery or email.lower() == recovery.lower():
                status.config(text="Enter two different email addresses.")
                return

            self._setup_pw = pw1
            self._setup_meta = {"email": email, "recovery_email": recovery}
            self.build_smtp_setup_screen()

        tk.Button(self.container, text="Next: set up sender email", command=do_setup).pack(pady=10)

    def build_smtp_setup_screen(self):
        self.clear()
        tk.Label(self.container, text="Email Sender Setup", font=("Segoe UI", 14, "bold")).pack(pady=(0, 4))
        tk.Label(self.container, text="For Gmail, use an App Password (not your normal one).",
                 wraplength=380, fg="gray").pack(pady=(0, 10))

        fields = {}

        def add_field(label, default="", show=None):
            tk.Label(self.container, text=label, anchor="w").pack(fill="x")
            e = tk.Entry(self.container, show=show)
            e.insert(0, default)
            e.pack(fill="x", pady=(0, 6))
            fields[label] = e

        add_field("SMTP host", default="smtp.gmail.com")
        add_field("SMTP port", default="465")
        add_field("Sender email address")
        add_field("Sender app password", show="*")

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def do_save():
            try:
                port = int(fields["SMTP port"].get().strip())
            except ValueError:
                status.config(text="Port must be a number (e.g. 465).")
                return

            self._setup_meta["smtp"] = {
                "host": fields["SMTP host"].get().strip(),
                "port": port,
                "user": fields["Sender email address"].get().strip(),
                "password": fields["Sender app password"].get().replace(" ", "").strip(),
            }

            salt = os.urandom(16)
            key = vault._derive_key(self._setup_pw, salt)
            verifier = hashlib.sha256(key).hexdigest()
            store = {
                "salt": base64.b64encode(salt).decode("utf-8"),
                "verifier": verifier,
                "enc_meta": vault._encrypt_meta(key, self._setup_meta),
                "blob": "",
            }
            vault._save_store(store)
            messagebox.showinfo("Setup complete", "Vault created. You can now log in.")
            self.build_initial_screen()

        tk.Button(self.container, text="Finish setup", command=do_save).pack(pady=10)

    # ---------- login ----------

    def build_login_screen(self, store):
        self.clear()
        tk.Label(self.container, text="Secret Locker", font=("Segoe UI", 16, "bold")).pack(pady=(10, 20))

        tk.Label(self.container, text="Vault password").pack(anchor="w")
        pw_entry = tk.Entry(self.container, show="*")
        pw_entry.pack(fill="x", pady=(0, 10))
        pw_entry.focus()

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def try_unlock():
            salt = base64.b64decode(store["salt"])
            key = vault._derive_key(pw_entry.get(), salt)
            verifier = hashlib.sha256(key).hexdigest()
            if verifier != store["verifier"]:
                status.config(text="Incorrect password.")
                return
            try:
                meta_dict = vault._decrypt_meta(key, store["enc_meta"])
            except vault.InvalidToken:
                status.config(text="Could not read vault metadata.")
                return
            self.current_key = key
            self.meta_dict = meta_dict
            self.pending_purpose = "unlock"
            self.send_otp_and_show_screen(meta_dict["email"], meta_dict["smtp"])

        pw_entry.bind("<Return>", lambda e: try_unlock())
        tk.Button(self.container, text="Unlock", command=try_unlock).pack(fill="x", pady=(4, 4))
        tk.Button(self.container, text="Change password", command=lambda: self.build_change_password_screen(store)).pack(fill="x")
        tk.Button(self.container, text="Update sender email settings", command=lambda: self.build_update_smtp_entry(store)).pack(fill="x", pady=(4, 0))

    # ---------- update sender email settings ----------

    def build_update_smtp_entry(self, store):
        self.clear()
        tk.Label(self.container, text="Update Sender Email", font=("Segoe UI", 14, "bold")).pack(pady=(10, 10))
        tk.Label(self.container, text="Confirm your vault password first").pack(anchor="w")
        pw_entry = tk.Entry(self.container, show="*")
        pw_entry.pack(fill="x", pady=(0, 10))
        pw_entry.focus()

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def proceed():
            salt = base64.b64decode(store["salt"])
            key = vault._derive_key(pw_entry.get(), salt)
            verifier = hashlib.sha256(key).hexdigest()
            if verifier != store["verifier"]:
                status.config(text="Incorrect password.")
                return
            try:
                meta_dict = vault._decrypt_meta(key, store["enc_meta"])
            except vault.InvalidToken:
                status.config(text="Could not read vault metadata.")
                return
            self.current_key = key
            self.build_update_smtp_form(store, meta_dict)

        pw_entry.bind("<Return>", lambda e: proceed())
        tk.Button(self.container, text="Continue", command=proceed).pack(fill="x", pady=(4, 4))
        tk.Button(self.container, text="Back", command=self.build_initial_screen).pack(fill="x")

    def build_update_smtp_form(self, store, meta_dict):
        self.clear()
        tk.Label(self.container, text="Sender Email Settings", font=("Segoe UI", 14, "bold")).pack(pady=(0, 10))

        fields = {}
        smtp = meta_dict.get("smtp", {})

        def add_field(label, default="", show=None):
            tk.Label(self.container, text=label, anchor="w").pack(fill="x")
            e = tk.Entry(self.container, show=show)
            e.insert(0, str(default))
            e.pack(fill="x", pady=(0, 6))
            fields[label] = e

        add_field("SMTP host", default=smtp.get("host", "smtp.gmail.com"))
        add_field("SMTP port", default=smtp.get("port", 465))
        add_field("Sender email address", default=smtp.get("user", ""))
        add_field("Sender app password (leave blank to keep current)", show="*")

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def save():
            try:
                port = int(fields["SMTP port"].get().strip())
            except ValueError:
                status.config(text="Port must be a number.")
                return
            new_pw = fields["Sender app password (leave blank to keep current)"].get().replace(" ", "").strip()
            meta_dict["smtp"] = {
                "host": fields["SMTP host"].get().strip(),
                "port": port,
                "user": fields["Sender email address"].get().strip(),
                "password": new_pw if new_pw else smtp.get("password", ""),
            }
            store["enc_meta"] = vault._encrypt_meta(self.current_key, meta_dict)
            vault._save_store(store)
            self.current_key = None
            messagebox.showinfo("Updated", "Sender email settings updated.")
            self.build_initial_screen()

        tk.Button(self.container, text="Save changes", command=save).pack(fill="x", pady=(4, 4))
        tk.Button(self.container, text="Cancel", command=self.build_initial_screen).pack(fill="x")

    # ---------- OTP screen (shared) ----------

    def send_otp_and_show_screen(self, to_email, smtp_cfg):
        self.clear()
        tk.Label(self.container, text="Verification Code", font=("Segoe UI", 14, "bold")).pack(pady=(10, 4))
        info = tk.Label(self.container, text=f"Sending code to {to_email} ...", fg="gray", wraplength=380)
        info.pack(pady=(0, 10))
        self.update()

        otp = vault.generate_otp()
        self.pending_otp = otp
        self.pending_expiry = time.time() + vault.OTP_VALID_SECONDS
        self.pending_attempts = 3

        def send_it():
            try:
                vault.send_otp_email(to_email, otp, smtp_cfg)
                info.config(text=f"Code sent to {to_email}. It expires in 5 minutes.")
            except Exception as e:
                info.config(text=f"Failed to send email: {e}", fg="red")

        threading.Thread(target=send_it, daemon=True).start()

        tk.Label(self.container, text="Enter 6-digit OTP").pack(anchor="w")
        otp_entry = tk.Entry(self.container)
        otp_entry.pack(fill="x", pady=(0, 10))
        otp_entry.focus()

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def verify():
            if time.time() > self.pending_expiry:
                status.config(text="OTP expired. Go back and try again.")
                return
            if otp_entry.get().strip() == self.pending_otp:
                if self.pending_purpose == "unlock":
                    self.show_unlocked_screen()
                elif self.pending_purpose == "change_password":
                    self.finish_change_password()
                return
            self.pending_attempts -= 1
            if self.pending_attempts <= 0:
                status.config(text="Too many wrong attempts. Go back and try again.")
            else:
                status.config(text=f"Incorrect OTP. {self.pending_attempts} attempt(s) left.")

        otp_entry.bind("<Return>", lambda e: verify())
        tk.Button(self.container, text="Verify", command=verify).pack(fill="x")
        tk.Button(self.container, text="Cancel", command=self.build_initial_screen).pack(fill="x", pady=(6, 0))

    # ---------- unlocked screen ----------

    def show_unlocked_screen(self):
        self.clear()
        vault.unlock_vault(self.current_key, self.store)
        tk.Label(self.container, text="Vault Unlocked", font=("Segoe UI", 14, "bold"), fg="green").pack(pady=(10, 6))
        tk.Label(self.container, text=vault.PLAIN_DIR, wraplength=380, fg="gray").pack(pady=(0, 16))

        def open_folder():
            os.makedirs(vault.PLAIN_DIR, exist_ok=True)
            os.startfile(vault.PLAIN_DIR)

        tk.Button(self.container, text="Open vault folder", command=open_folder).pack(fill="x", pady=(0, 8))

        def do_lock():
            vault.lock_vault(self.current_key, self.store)
            self.current_key = None
            messagebox.showinfo("Locked", "Vault locked. Plaintext files wiped.")
            self.build_initial_screen()

        tk.Button(self.container, text="Lock vault", command=do_lock, bg="#c0392b", fg="white").pack(fill="x")
        tk.Label(self.container, text="Don't forget to Lock before closing this app.",
                 fg="gray", wraplength=380).pack(pady=(16, 0))

    # ---------- change password ----------

    def build_change_password_screen(self, store):
        self.clear()
        tk.Label(self.container, text="Change Password", font=("Segoe UI", 14, "bold")).pack(pady=(10, 10))
        tk.Label(self.container, text="Current password").pack(anchor="w")
        old_pw = tk.Entry(self.container, show="*")
        old_pw.pack(fill="x", pady=(0, 10))

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def proceed():
            salt = base64.b64decode(store["salt"])
            key = vault._derive_key(old_pw.get(), salt)
            verifier = hashlib.sha256(key).hexdigest()
            if verifier != store["verifier"]:
                status.config(text="Incorrect current password.")
                return
            try:
                meta_dict = vault._decrypt_meta(key, store["enc_meta"])
            except vault.InvalidToken:
                status.config(text="Could not read vault metadata.")
                return
            recovery_email = meta_dict.get("recovery_email")
            if not recovery_email:
                status.config(text="No recovery email set on this vault.")
                return
            self.current_key = key
            self.meta_dict = meta_dict
            self.pending_purpose = "change_password"
            self.ask_new_password_then_otp(recovery_email, meta_dict["smtp"])

        tk.Button(self.container, text="Continue", command=proceed).pack(fill="x", pady=(4, 4))
        tk.Button(self.container, text="Back", command=self.build_initial_screen).pack(fill="x")

    def ask_new_password_then_otp(self, recovery_email, smtp_cfg):
        self.clear()
        tk.Label(self.container, text="Set New Password", font=("Segoe UI", 14, "bold")).pack(pady=(10, 10))
        tk.Label(self.container, text="New password").pack(anchor="w")
        pw1 = tk.Entry(self.container, show="*")
        pw1.pack(fill="x", pady=(0, 6))
        tk.Label(self.container, text="Confirm new password").pack(anchor="w")
        pw2 = tk.Entry(self.container, show="*")
        pw2.pack(fill="x", pady=(0, 10))

        status = tk.Label(self.container, text="", fg="red")
        status.pack()

        def next_step():
            if len(pw1.get()) < 8:
                status.config(text="Password must be at least 8 characters.")
                return
            if pw1.get() != pw2.get():
                status.config(text="Passwords don't match.")
                return
            self.pending_new_pw = pw1.get()
            self.send_otp_and_show_screen(recovery_email, smtp_cfg)

        tk.Button(self.container, text="Send recovery code & continue", command=next_step).pack(fill="x")

    def finish_change_password(self):
        old_key = self.current_key
        new_pw = self.pending_new_pw
        store = self.store
        meta_dict = self.meta_dict

        old_fernet = vault.Fernet(old_key)
        new_salt = os.urandom(16)
        new_key = vault._derive_key(new_pw, new_salt)
        new_fernet = vault.Fernet(new_key)

        blob_b64 = store.get("blob", "")
        if blob_b64:
            try:
                data = old_fernet.decrypt(base64.b64decode(blob_b64))
                store["blob"] = base64.b64encode(new_fernet.encrypt(data)).decode("utf-8")
            except vault.InvalidToken:
                pass

        store["enc_meta"] = vault._encrypt_meta(new_key, meta_dict)
        store["salt"] = base64.b64encode(new_salt).decode("utf-8")
        store["verifier"] = hashlib.sha256(new_key).hexdigest()
        vault._save_store(store)

        self.current_key = None
        self.pending_new_pw = None
        messagebox.showinfo("Success", "Password changed. Vault re-encrypted under the new password.")
        self.build_initial_screen()


if __name__ == "__main__":
    app = VaultApp()
    app.mainloop()
