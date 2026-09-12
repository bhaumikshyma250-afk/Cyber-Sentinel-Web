import os
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates
from pydantic import BaseModel
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

app = FastAPI(title="Cyber Sentinel AI")

# --- DYNAMIC TEMPLATE PATH RESOLUTION ---
BASE_DIR = Path(__file__).resolve().parent
template_dir = BASE_DIR / "templates"
if not template_dir.exists() or not (template_dir / "index.html").exists():
    template_dir = BASE_DIR

templates = Jinja2Templates(directory=str(template_dir))
DB_PATH = BASE_DIR / "sentinel.db"

# --- INDIAN STANDARD TIMEZONE (+5:30) ---
IST = timezone(timedelta(hours=5, minutes=30))

# --- 1. SQLITE DATABASE ENGINE ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            scanned_text TEXT,
            threat_score INTEGER,
            risk_level TEXT,
            action TEXT,
            flags TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def save_log(text: str, score: int, level: str, action: str, flags: list):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Server UTC holeo IST time-e format hobe: 12-Sep-2026 06:22 PM
    current_ist = datetime.now(IST).strftime("%d-%b-%Y %I:%M %p")
    
    cursor.execute("""
        INSERT INTO scan_logs (timestamp, scanned_text, threat_score, risk_level, action, flags)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        current_ist,
        text[:140],
        score,
        level,
        action,
        ", ".join(flags)
    ))
    conn.commit()
    conn.close()

def get_recent_logs(limit: int = 10):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, scanned_text, threat_score, risk_level FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{"time": r[0], "text": r[1], "score": r[2], "level": r[3]} for r in rows]

def clear_db_logs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_logs")
    conn.commit()
    conn.close()

# --- 2. ML SPAM & PHISHING CLASSIFIER ---
train_texts = [
    "Win free cash prize lottery claim urgently now",
    "Your bank account is suspended verify password immediately",
    "Exclusive offer get free iPhone reward click link http://free-prize.xyz",
    "Dear customer update your KYC to avoid card blocking https://bit.ly/kyc-alert",
    "Click here to claim 50000 cash http://lottery-winner.top",
    "Login to your bank account securely http://verify-secure-bank.live/login",
    "Urgent action required on your account verify credentials",
    "Hey, what time is the CST lab class tomorrow?",
    "Please send the assignment notes when free",
    "Let's meet at the college canteen",
    "Sir has uploaded the mid-term question bank",
    "Can you share the lecture slides for data structures?",
    "Google search homepage https://www.google.com",
    "Check Python official documentation https://docs.python.org"
]
labels = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]

vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(train_texts)
ml_model = MultinomialNB()
ml_model.fit(X, labels)

# --- 3. PATTERNS & REGEX DETECTORS ---
PATTERNS = {
    "SUSPICIOUS_DOMAIN_TLD": r"\b[a-zA-Z0-9.-]+\.(xyz|top|live|info|biz|tk|ml|ga|cf|gq|club|work|link|click|site|download|review)\b",
    "SHORTENED_URL": r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly|rb\.gy|cutt\.ly)\b",
    "IP_ADDRESS_URL": r"http[s]?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    "GENERIC_WEB_LINK": r"(https?:\/\/[^\s]+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*)",
    "URGENCY_KEYWORD": r"\b(urgent|suspended|blocked|kyc|verify|lottery|winner|otp|reward|free|claim|action required|password|bank|alert|login)\b",
    "SQL_INJECTION": r"(\bOR\b|\bUNION\b|\bSELECT\b).*[='\"].*;",
    "XSS_SCRIPT": r"<script\b[^>]*>(.*?)</script>"
}

class ScanRequest(BaseModel):
    text: str

# --- 4. THREAT SCORING ENGINE ---
def analyze_text(text: str):
    score = 0
    matched_flags = []

    for category, pattern in PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            if category in ["SUSPICIOUS_DOMAIN_TLD", "SHORTENED_URL", "IP_ADDRESS_URL"]:
                score += 45
            elif category == "URGENCY_KEYWORD":
                score += 35
            elif category == "GENERIC_WEB_LINK":
                score += 25
            else:
                score += 30
            matched_flags.append(category)

    transformed = vectorizer.transform([text])
    prob = ml_model.predict_proba(transformed)[0][1]
    score += int(prob * 45)

    final_score = min(score, 100)

    if final_score >= 70:
        level, color, action = "CRITICAL THREAT", "red", "BLOCK / DO NOT CLICK"
    elif final_score >= 35:
        level, color, action = "SUSPICIOUS", "yellow", "VERIFY SOURCE"
    else:
        level, color, action = "SAFE", "green", "SAFE TO VIEW"

    flags_result = matched_flags or ["No malicious patterns detected"]
    save_log(text, final_score, level, action, flags_result)

    return {
        "score": final_score,
        "level": level,
        "color": color,
        "action": action,
        "flags": flags_result
    }

# --- 5. ROUTES ---
@app.get("/", response_class=HTMLResponse)
async def serve_home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/scan")
async def scan_endpoint(data: ScanRequest):
    return analyze_text(data.text)

@app.get("/api/logs")
async def fetch_logs():
    return get_recent_logs()

@app.delete("/api/logs")
async def delete_logs_endpoint():
    clear_db_logs()
    return {"status": "success", "message": "All logs cleared successfully"}