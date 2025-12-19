# 🛡️ AI-Powered Deceptive Honeypot & IDS

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.68%2B-green)
![ML](https://img.shields.io/badge/AI-RandomForest-orange)

An advanced **Intrusion Detection System (IDS)** that combines Machine Learning with a deceptive **Honeypot** environment.  
It detects malicious login attempts (SQL Injection, XSS, Brute Force) and silently redirects attackers to a fake internal dashboard, while legitimate users access the real system.

---

## ✨ Key Features

### 🛡️ Defense: The Honey Pot (Backend)
- **Hybrid Detection Engine:** Uses a **Random Forest** ML model (TF-IDF vectorization) combined with Regex-based pattern matching to detect zero-day payloads.
- **Smart Deception (Honeypot):**
  - **Attacker View:** Malicious users are redirected to a **fake internal portal** populated with generated confidential-looking files and emails.
  - **Red Mark Removal:** No visual warnings are shown, keeping the portal indistinguishable from the real system.
- **Forensic Logging:** Logs **IP address, city, ISP, and payload** to both an Excel sheet and SQLite database.
- **Universal API:** Secure endpoint (`/api/analyze`) for integration with external websites (React, WordPress, etc.).
- **Secure Admin CLI:** Command-line tool (`manage_users.py`) for managing admins and uploading real files securely.

### ⚔️ Offense: Attack Simulator
- **Automated Pentesting:** Generates thousands of SQL Injection, XSS, and Brute Force attack payloads.
- **Traffic Simulation:** Mimics realistic attacker behavior to test AI accuracy and rate limiting.


---

## 🚀 Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/aayushchavanke/AI-Intrusion-Detection-System.git
cd AI-Intrusion-Detection-System
```

### 2️⃣ Setup "The Honey Pot"
```bash
cd "The Honey Pot"
pip install -r requirements.txt
```

### 3️⃣ Initialize the System
```bash
python manage_users.py
```
- Select **Option 1** to create an Admin user  
- Select **Option 4** to upload genuine files

### 4️⃣ Run the Server
```bash
python -m uvicorn app.main:app --reload
```

The application will run at: **http://127.0.0.1:8000**

---

## 🧠 How It Works

1. **Traffic Analysis:** Every login request is intercepted by middleware.
2. **AI Prediction:** Payload is vectorized and analyzed by the Random Forest model.
3. **Decision Logic:**
   - ✅ **Normal User:** Valid credentials → Real Dashboard
   - ❌ **Attacker:** Malicious payload → Honeypot Dashboard
   - ⚠️ **Auth Fail:** Incorrect credentials → Generic error
4. **Logging:** Attacker data is stored in `Attack_Logs.xlsx` and SQLite.


---

## 📝 License
This project is intended **strictly for educational and research purposes**.
