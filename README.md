# 🔐 Password Manager

A simple yet secure command-line password manager built with Python. It uses a **master password** to protect access, and stores all credentials encrypted in a JSON file. If an unauthorized user fails to enter the correct master password more than **5 times**, all stored data is securely deleted to prevent brute-force attacks.

---

## 📦 Environment

This project uses Python's built-in `venv` for environment isolation.  
To create and activate the environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

```
## 🚀 How to Run
To start the application, simply execute:

```bash
python3 manager.py

```

## 🛠️ How It Works

### First Time Use:
You'll be prompted to create a master password. This is your only way to access the stored credentials.

### Main Options:

➕ Add a new password (e.g., for a website or service).

📂 View all saved passwords.

❌ Delete an existing password entry.

### Security Feature:

If the master password is entered incorrectly more than 5 times, the encrypted storage file (.json) is automatically deleted for safety.



## 📁 File Structure

```bash
├── manager.py
├── passwords.json        # Encrypted storage file (auto-created)
├── venv/                 # Virtual environment
└── README.md


```


## ✅ Requirements

Python 3.7+

Modules: cryptography, json, etc.


## 🔐 Important
Always remember your master password!
There is no recovery mechanism by design, to preserve security.



## 📄 License
This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).
You are free to share and adapt the code, but commercial use is strictly prohibited.




