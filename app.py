from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import hashlib
import re
import math
import string
import secrets
import os

app = Flask(__name__)
CORS(app)

DB_PATH = "passwords.db"

# ─── Database Setup ────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def is_password_reused(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ph = hash_password(password)
    c.execute(
        "SELECT 1 FROM password_history WHERE username=? AND password_hash=?",
        (username, ph)
    )
    result = c.fetchone()
    conn.close()
    return result is not None

def save_password(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ph = hash_password(password)
    c.execute(
        "INSERT INTO password_history (username, password_hash) VALUES (?, ?)",
        (username, ph)
    )
    conn.commit()
    conn.close()

def get_history_count(username: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM password_history WHERE username=?", (username,))
    count = c.fetchone()[0]
    conn.close()
    return count

# ─── Password Analysis ─────────────────────────────────────────────────────────

COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password123", "welcome", "admin", "login", "hello",
    "ninja", "mustang", "access", "000000", "pussy", "batman"
}

def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password):    charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0:
        return 0
    return len(password) * math.log2(charset)

def analyze_password(password: str, username: str = "") -> dict:
    length = len(password)
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    is_common   = password.lower() in COMMON_PASSWORDS
    entropy     = calculate_entropy(password)

    # Detect patterns
    has_sequential = bool(re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def)', password.lower()))
    has_repeated   = bool(re.search(r'(.)\1{2,}', password))
    has_keyboard   = bool(re.search(r'(qwerty|asdfg|zxcvb|qwert|asdf)', password.lower()))

    checks = {
        "length_8":        length >= 8,
        "length_12":       length >= 12,
        "length_16":       length >= 16,
        "has_lowercase":   has_lower,
        "has_uppercase":   has_upper,
        "has_digit":       has_digit,
        "has_special":     has_special,
        "not_common":      not is_common,
        "no_sequential":   not has_sequential,
        "no_repeated":     not has_repeated,
        "no_keyboard":     not has_keyboard,
        "good_entropy":    entropy >= 50,
    }

    score = sum([
        min(length, 16) * 2,
        10 if has_lower  else 0,
        10 if has_upper  else 0,
        10 if has_digit  else 0,
        15 if has_special else 0,
        -20 if is_common else 0,
        -10 if has_sequential else 0,
        -8  if has_repeated else 0,
        -8  if has_keyboard else 0,
        min(entropy, 40),
    ])
    score = max(0, min(score, 100))

    if score < 20:   strength, color = "Very Weak",  "#ff2d55"
    elif score < 40: strength, color = "Weak",        "#ff6b35"
    elif score < 60: strength, color = "Fair",        "#ffd60a"
    elif score < 80: strength, color = "Strong",      "#34c759"
    else:            strength, color = "Very Strong", "#30d158"

    suggestions = []
    if length < 12:        suggestions.append("Use at least 12 characters for better security")
    if not has_upper:      suggestions.append("Add uppercase letters (A-Z)")
    if not has_lower:      suggestions.append("Add lowercase letters (a-z)")
    if not has_digit:      suggestions.append("Include numbers (0-9)")
    if not has_special:    suggestions.append("Add special characters (!@#$%^&*)")
    if is_common:          suggestions.append("This is a commonly used password — avoid it")
    if has_sequential:     suggestions.append("Avoid sequential patterns like '123' or 'abc'")
    if has_repeated:       suggestions.append("Avoid repeated characters like 'aaa'")
    if has_keyboard:       suggestions.append("Avoid keyboard patterns like 'qwerty'")
    if entropy < 50:       suggestions.append("Increase complexity to improve entropy")

    reused = False
    if username:
        reused = is_password_reused(username, password)
        if reused:
            suggestions.insert(0, "⚠️ This password has been used before for this account")

    return {
        "score": round(score),
        "strength": strength,
        "color": color,
        "entropy": round(entropy, 1),
        "length": length,
        "checks": checks,
        "suggestions": suggestions,
        "is_reused": reused,
        "char_types": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digit,
            "special": has_special,
        }
    }

def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (re.search(r'[a-z]', pwd) and re.search(r'[A-Z]', pwd) and
                re.search(r'\d', pwd) and re.search(r'[^a-zA-Z0-9]', pwd)):
            return pwd

def generate_passphrase() -> str:
    words = [
        "tiger","ocean","spark","crisp","mango","storm","pixel","blaze",
        "frosty","gravel","lunar","prism","swift","noble","vivid","quartz",
        "ember","forge","glade","haven","ivory","jolt","knack","lofty"
    ]
    chosen = [secrets.choice(words) for _ in range(4)]
    chosen[0] = chosen[0].capitalize()
    num = secrets.randbelow(900) + 100
    sym = secrets.choice("!@#$%&*")
    return f"{''.join(chosen)}{num}{sym}"

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    with open("templates/index.html", encoding="utf-8") as f:
        return f.read()

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data     = request.get_json()
    password = data.get("password", "")
    username = data.get("username", "").strip()
    if not password:
        return jsonify({"error": "No password provided"}), 400
    result = analyze_password(password, username)
    return jsonify(result)

@app.route("/api/save", methods=["POST"])
def api_save():
    data     = request.get_json()
    password = data.get("password", "")
    username = data.get("username", "").strip()
    if not password or not username:
        return jsonify({"error": "Username and password required"}), 400
    if is_password_reused(username, password):
        return jsonify({"success": False, "message": "Password already used before"}), 200
    save_password(username, password)
    count = get_history_count(username)
    return jsonify({"success": True, "message": "Password saved to history", "history_count": count})

@app.route("/api/generate", methods=["GET"])
def api_generate():
    length = int(request.args.get("length", 16))
    length = max(12, min(length, 32))
    return jsonify({
        "password":   generate_strong_password(length),
        "passphrase": generate_passphrase(),
    })

@app.route("/api/history/<username>", methods=["GET"])
def api_history(username):
    count = get_history_count(username)
    return jsonify({"username": username, "saved_passwords": count})

# ─── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    os.makedirs("templates", exist_ok=True)
    print("\n✅  Password Strength Analyzer running at http://localhost:5000\n")
    app.run(host="0.0.0.0", port=10000, debug=False)
