# Secret Locker 🔒

A personal file vault protected by **password + email OTP (two-factor)**.
Everything — your files, your email addresses, and even the sender email's
credentials — is stored encrypted inside a **single file**: `myvault.dat`.
Open it in Notepad and it's unreadable garbage; nothing about the vault is
visible without the correct password.

---

## Features

- 🔐 Password + one-time email code (2FA) to unlock
- 📦 Single encrypted file (`myvault.dat`) — no visible folder structure
- 🔁 New OTP generated every single unlock, expires in 5 minutes
- 🔑 Change password anytime (requires old password + a recovery-email OTP)
- ✉️ Update sender email/app-password anytime without resetting the vault
- 🖥️ Both a GUI app (`vault_gui.py`) and a terminal version (`vault.py`)
- 🧩 One-click desktop launcher (`OpenVault.bat` + Windows shortcut)

## How it works

1. You enter your **vault password**.
2. A random 6-digit **OTP** is emailed to your primary address.
3. Enter the OTP → vault unlocks → your files appear in a `vault_plain`
   folder to use freely.
4. Click **Lock** → files are re-encrypted back into `myvault.dat` and the
   plaintext folder is deleted.

Encryption: AES (via Python's `cryptography` Fernet), with the key derived
from your password using PBKDF2-HMAC-SHA256 (390,000 iterations) + a random
salt. Nothing is decryptable without the correct password.

---

## Requirements

- Python 3.9+
- The `cryptography` package
- A Gmail (or other SMTP) account to send OTP codes from

## Setup

### 1. Install Python
Download from [python.org/downloads](https://python.org/downloads).
**Important:** on the installer's first screen, tick **"Add python.exe to PATH"**.

### 2. Get the project files
Clone this repo, or download `vault.py`, `vault_gui.py`, `OpenVault.bat`,
and `requirements.txt` into one folder.

### 3. Install the dependency
```
pip install -r requirements.txt
```

### 4. Create a Gmail App Password
This is the account the OTP emails will be sent **from**.
1. Go to [myaccount.google.com/security](https://myaccount.google.com/security)
   and confirm **2-Step Verification** is turned on (required for app passwords).
2. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
3. Name it anything, click **Create**.
4. Copy the 16-character code shown — you'll paste it into setup.

### 5. Run first-time setup
```
python vault_gui.py
```
(or `python vault.py` for the terminal version)

You'll be asked for:

| Field | Notes |
|---|---|
| Vault password | Min 8 characters. Never stored — only a salted hash. |
| Primary email | Where every unlock's OTP is sent. |
| Recovery email | A **different** address, used only for password changes. |
| SMTP host | `smtp.gmail.com` for Gmail |
| SMTP port | **465** (SSL) — some networks block the more common port 587 |
| Sender email | The Gmail account you made the app password with |
| Sender app password | The 16-character code from step 4 |

Setup complete — `myvault.dat` now holds your fully encrypted vault.

### 6. (Optional) One-click desktop launcher
1. Make sure `OpenVault.bat` is in the same folder.
2. Right-click it → **Send to** → **Desktop (create shortcut)**.
3. Double-click the shortcut anytime to open the app directly — no terminal needed.

---

## Everyday use

1. Open the app (`python vault_gui.py` or your desktop shortcut).
2. Click **Unlock**, enter your password.
3. Check your primary email for the 6-digit OTP, enter it.
4. Click **Open vault folder** — use your files.
5. Click **Lock vault** when done. **Always lock before closing** — otherwise
   your files stay decrypted on disk.

## Changing your password

Login screen → **Change password** → enter current password → enter the OTP
sent to your **recovery** email → set a new password. All existing files are
automatically re-encrypted under the new password.

## Rotating your sender app password

Login screen → **Update sender email settings** → confirm your vault password
→ paste a new app password (leave blank to keep the current one) → Save.
Useful if an old app password was ever exposed (e.g. accidentally shared) —
revoke it on Google's side and swap it in here.

---

## Security notes (read before trusting sensitive files to this)

- This is a solid **personal/DIY** protection layer — good against casual
  snooping, family/friends, or a lost/stolen drive. It is **not** rated
  against a skilled attacker with malware or physical access to your
  unlocked PC.
- There is **no password recovery** if you forget your password and lose
  access to both your primary and recovery email. Store your password in a
  password manager.
- `myvault.dat` is the entire vault. **Back it up** (e.g. to another drive
  or cloud storage) — the file stays encrypted even in a backup, so this is
  safe. If you lose this file with no backup, your data is unrecoverable.
- Never commit `myvault.dat` to a public repository (see `.gitignore` below).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `535 Username and Password not accepted` | Double-check the sender email has no typo, and the app password has no stray spaces. Confirm 2-Step Verification is on. |
| `SSLEOFError` on port 587 | Some mobile networks block port 587 — use port **465** instead (already the default here). |
| Password prompt seems frozen / typing does nothing | Known VS Code terminal issue with hidden password input on some systems — this project avoids it by showing passwords in plain text as you type. |
| App can't find `vault.py` | Make sure `vault_gui.py` sits in the **same folder** as `vault.py` — it imports it directly. |

---

## Project structure

```
├── vault.py            # Core logic + terminal interface
├── vault_gui.py         # GUI (Tkinter) interface — requires vault.py
├── OpenVault.bat        # One-click launcher (Windows)
├── requirements.txt
└── myvault.dat           # Created after setup — YOUR encrypted vault (never commit this)
```

## License

MIT — free to use, modify, and share.
