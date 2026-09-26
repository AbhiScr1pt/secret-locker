#!/usr/bin/env python3
"""
Secret Locker - single-file version (fully encrypted metadata)
------------------------------------------------------------------
Everything (emails, sender credentials, and your files) lives in ONE file:
myvault.dat - and ALL of it is encrypted, not just your documents.
Only your password + salt can unlock any of it.

Run:
    python vault.py
"""

import os
import json
import base64
import random
import smtplib
import shutil
import hashlib
import time
import zipfile
import io
from email.mime.text import MIMEText

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_PATH = os.path.join(BASE_DIR, "myvault.dat")
PLAIN_DIR = os.path.join(BASE_DIR, "vault_plain")  # only exists while unlocked

OTP_VALID_SECONDS = 300
OTP_LENGTH = 6


# ---------- helpers ----------

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _load_store():
    if not os.path.exists(VAULT_PATH):
        return None
    with open(VAULT_PATH, "r") as f:
        return json.load(f)


def _save_store(store):
    with open(VAULT_PATH, "w") as f:
        json.dump(store, f)


def _encrypt_meta(key, meta_dict):
    fernet = Fernet(key)
    data = json.dumps(meta_dict).encode("utf-8")
    return base64.b64encode(fernet.encrypt(data)).decode("utf-8")


def _decrypt_meta(key, enc_meta_b64):
    fernet = Fernet(key)
    data = fernet.decrypt(base64.b64decode(enc_meta_b64))
    return json.loads(data.decode("utf-8"))


# ---------- zip helpers ----------

def _zip_dir_to_bytes(folder):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.isdir(folder):
            for name in os.listdir(folder):
                path = os.path.join(folder, name)
                if os.path.isfile(path):
                    zf.write(path, arcname=name)
    return buf.getvalue()


def _unzip_bytes_to_dir(data, folder):
    os.makedirs(folder, exist_ok=True)
    buf = io.BytesIO(data)
    with zipfile.ZipFile(buf, "r") as zf:
        zf.extractall(folder)


# ---------- setup (first run) ----------

def first_time_setup():
    print("=== First-time Vault Setup ===")
    print("This creates your single-file locker. Choose a strong password;")
    print("it is never stored, only a salted hash of it.\n")

    while True:
        pw1 = input("Set vault password: ")
        pw2 = input("Confirm password: ")
        if pw1 != pw2:
            print("Passwords don't match, try again.\n")
            continue
        if len(pw1) < 8:
            print("Use at least 8 characters.\n")
            continue
        break

    email = input("Primary email address to receive OTP codes: ").strip()
    while True:
        recovery_email = input("Recovery email (must be different, used only for password changes): ").strip()
        if recovery_email and recovery_email.lower() != email.lower():
            break
        print("Recovery email must be different from your primary email.\n")

    print("\nNow set up the email sender (the account the OTP will be sent FROM).")
    print("For Gmail: use an App Password, not your normal password.")
    print("https://myaccount.google.com/apppasswords\n")
    smtp_host = input("SMTP host (e.g. smtp.gmail.com): ").strip()
    smtp_port = input("SMTP port (use 465 for Gmail): ").strip()
    smtp_user = input("Sender email address: ").strip()
    smtp_pass = input("Sender app password: ").replace(" ", "").strip()

    salt = os.urandom(16)
    key = _derive_key(pw1, salt)
    verifier = hashlib.sha256(key).hexdigest()

    meta_dict = {
        "email": email,
        "recovery_email": recovery_email,
        "smtp": {
            "host": smtp_host,
            "port": int(smtp_port),
            "user": smtp_user,
            "password": smtp_pass,
        },
    }

    store = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "verifier": verifier,
        "enc_meta": _encrypt_meta(key, meta_dict),
        "blob": "",
    }
    _save_store(store)

    print(f"\nSetup complete. Everything is stored (encrypted) in: {VAULT_PATH}")
    print("Run the script again to unlock your vault.")


# ---------- OTP ----------

def generate_otp():
    return "".join(str(random.randint(0, 9)) for _ in range(OTP_LENGTH))


def send_otp_email(to_email, otp, smtp_cfg):
    msg = MIMEText(f"Your vault OTP code is: {otp}\nIt expires in 5 minutes.")
    msg["Subject"] = "Your Vault OTP Code"
    msg["From"] = smtp_cfg["user"]
    msg["To"] = to_email

    with smtplib.SMTP_SSL(smtp_cfg["host"], smtp_cfg["port"]) as server:
        server.login(smtp_cfg["user"], smtp_cfg["password"])
        server.sendmail(smtp_cfg["user"], [to_email], msg.as_string())


def verify_otp_flow(email, smtp_cfg):
    otp = generate_otp()
    expires_at = time.time() + OTP_VALID_SECONDS

    try:
        send_otp_email(email, otp, smtp_cfg)
        print(f"OTP sent to {email}. It expires in {OTP_VALID_SECONDS // 60} minutes.")
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False

    attempts = 3
    while attempts > 0:
        if time.time() > expires_at:
            print("OTP expired.")
            return False
        entered = input("Enter OTP: ").strip()
        if entered == otp:
            return True
        attempts -= 1
        print(f"Incorrect OTP. {attempts} attempt(s) left.")
    return False


# ---------- password check ----------

def verify_password(store):
    salt = base64.b64decode(store["salt"])
    pw = input("Vault password: ")
    key = _derive_key(pw, salt)
    verifier = hashlib.sha256(key).hexdigest()
    if verifier != store["verifier"]:
        return None
    return key


# ---------- unlock / lock ----------

def unlock_vault(key, store):
    fernet = Fernet(key)
    os.makedirs(PLAIN_DIR, exist_ok=True)
    blob_b64 = store.get("blob", "")
    if blob_b64:
        try:
            data = fernet.decrypt(base64.b64decode(blob_b64))
            _unzip_bytes_to_dir(data, PLAIN_DIR)
        except InvalidToken:
            print("Warning: could not decrypt vault contents (corrupted or wrong key).")
    print(f"\nVault unlocked. Your files are in:\n  {PLAIN_DIR}")
    print("Add new files there too. When done, come back here and press Enter to lock.")


def lock_vault(key, store):
    fernet = Fernet(key)
    data = _zip_dir_to_bytes(PLAIN_DIR)
    store["blob"] = base64.b64encode(fernet.encrypt(data)).decode("utf-8")
    _save_store(store)

    if os.path.isdir(PLAIN_DIR):
        shutil.rmtree(PLAIN_DIR)

    print("Vault locked. Plaintext files wiped from disk.")


# ---------- change password ----------

def change_password_flow(store):
    print("\n=== Change Password ===")

    old_key = verify_password(store)
    if old_key is None:
        print("Incorrect current password. Cannot change password.")
        return

    try:
        meta_dict = _decrypt_meta(old_key, store["enc_meta"])
    except InvalidToken:
        print("Could not read vault metadata. Aborting.")
        return

    recovery_email = meta_dict.get("recovery_email")
    if not recovery_email:
        print("No recovery email is set up on this vault. Cannot proceed.")
        return

    print(f"Sending a verification code to your recovery email ({recovery_email})...")
    if not verify_otp_flow(recovery_email, meta_dict["smtp"]):
        print("Recovery verification failed. Password not changed.")
        return

    while True:
        pw1 = input("New vault password: ")
        pw2 = input("Confirm new password: ")
        if pw1 != pw2:
            print("Passwords don't match, try again.\n")
            continue
        if len(pw1) < 8:
            print("Use at least 8 characters.\n")
            continue
        break

    old_fernet = Fernet(old_key)
    new_salt = os.urandom(16)
    new_key = _derive_key(pw1, new_salt)
    new_fernet = Fernet(new_key)

    blob_b64 = store.get("blob", "")
    if blob_b64:
        try:
            data = old_fernet.decrypt(base64.b64decode(blob_b64))
            store["blob"] = base64.b64encode(new_fernet.encrypt(data)).decode("utf-8")
        except InvalidToken:
            print("Warning: could not decrypt existing vault contents with old key.")

    store["enc_meta"] = _encrypt_meta(new_key, meta_dict)
    store["salt"] = base64.b64encode(new_salt).decode("utf-8")
    store["verifier"] = hashlib.sha256(new_key).hexdigest()
    _save_store(store)

    print("Password changed successfully. Vault re-encrypted under the new password.")


# ---------- main ----------

def main():
    store = _load_store()
    if store is None:
        first_time_setup()
        return

    print("1) Unlock vault")
    print("2) Change password")
    choice = input("Choose (1/2, default 1): ").strip() or "1"

    if choice == "2":
        change_password_flow(store)
        return

    key = verify_password(store)
    if key is None:
        print("Incorrect password.")
        return

    try:
        meta_dict = _decrypt_meta(key, store["enc_meta"])
    except InvalidToken:
        print("Could not read vault metadata (corrupted file).")
        return

    if not verify_otp_flow(meta_dict["email"], meta_dict["smtp"]):
        print("OTP verification failed. Vault stays locked.")
        return

    unlock_vault(key, store)
    input("\nPress Enter here once you're done, to re-lock the vault... ")
    lock_vault(key, store)


if __name__ == "__main__":
    main()
