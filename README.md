## 🌐 Live Demo
👉 [Click here to try it live](https://password-analyzer-6rmx.onrender.com)

# 🔐 Password Strength Analyzer

A full-stack localhost tool to analyze, generate, and manage passwords securely.

---

## 📁 Project Structure

```
password-analyzer/
├── app.py               ← Flask backend (API + logic)
├── requirements.txt     ← Python dependencies
├── passwords.db         ← SQLite DB (auto-created on first run)
└── templates/
    └── index.html       ← Frontend UI
```

---

## ✅ Requirements

| Requirement | Version |
|-------------|---------|
| Python      | 3.8+    |
| pip         | latest  |
| Browser     | Any modern browser |

---

## 🚀 Setup & Run (Step by Step)

### Step 1 — Download / unzip the project
Place the `password-analyzer/` folder anywhere on your machine.

### Step 2 — Open a terminal in that folder
```bash
cd path/to/password-analyzer
```

### Step 3 — (Recommended) Create a virtual environment
```bash
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate

# macOS / Linux:
source venv/bin/activate
```

### Step 4 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Run the Flask server
```bash
python app.py
```

You should see:
```
✅  Password Strength Analyzer running at http://localhost:5000
```

### Step 6 — Open in your browser
```
http://localhost:5000
```

---

## 🔑 Features

### 🔍 Analyze
- Real-time strength meter (Very Weak → Very Strong)
- Entropy calculation (bits)
- 12-point security checklist
- Detects: common passwords, sequential patterns, repeated chars, keyboard walks
- Smart suggestions to improve the password

### ⚡ Generate
- **Random password** — cryptographically secure, configurable 12–32 characters
- **Passphrase** — 4 random words + number + symbol (easy to remember, hard to crack)
- One-click copy button

### 📂 Password History (SQLite)
- Enter a username → save hashed passwords to a local SQLite database
- Reuse detection: warns you if the same password was used before for that account
- Passwords are stored as **SHA-256 hashes only** — never plain text

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze` | Analyze a password |
| POST | `/api/save` | Save password hash to DB |
| GET | `/api/generate?length=16` | Generate strong password + passphrase |
| GET | `/api/history/<username>` | Get saved password count for a user |

### Example — Analyze
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "MyP@ssw0rd!", "username": "alice"}'
```

---

## 🛡️ Security Notes
- Passwords are **never stored in plain text** — only SHA-256 hashes
- The `passwords.db` file is local to your machine
- This tool is for **local use only** — do not expose it to the public internet without adding proper authentication
