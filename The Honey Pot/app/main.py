import time
import random
import joblib
import re
import shutil
import os
import pandas as pd
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, Depends, BackgroundTasks, UploadFile, File, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

# Local Imports
from .database import engine, get_db, AttackLog, RealUser, GenuineFile, Base
from .utils import (
    calculate_hash, 
    get_genuine_looking_response, 
    get_ip_location, 
    get_genuine_data, 
    get_fake_data,
    load_shadow_db  # Make sure this is importable from utils
)
from .sheets_logger import log_to_excel
from .schemas import LoginRequest, AnalysisResponse

Base.metadata.create_all(bind=engine)

app = FastAPI(title="The Honey Pot")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- AI MODEL LOADING ---
model = None
try: 
    model = joblib.load("app/model.pkl")
    print("[+] AI Model Loaded Successfully.")
except: 
    print("[-] AI Offline. Running in Heuristic Mode.")

request_history = {}

# --- HELPER FUNCTIONS ---
def apply_filters(query, time_range, specific_date_str):
    now = datetime.now()
    if specific_date_str:
        try: return query.filter(func.date(AttackLog.timestamp) == datetime.strptime(specific_date_str, "%Y-%m-%d").date())
        except: pass
    if time_range == "today": return query.filter(AttackLog.timestamp >= now.replace(hour=0, minute=0, second=0))
    elif time_range == "week": return query.filter(AttackLog.timestamp >= now - timedelta(days=7))
    elif time_range == "month": return query.filter(AttackLog.timestamp >= now - timedelta(days=30))
    return query

def check_rate_limit(ip):
    now = datetime.now()
    if ip not in request_history: request_history[ip] = []
    request_history[ip] = [t for t in request_history[ip] if now - t < timedelta(seconds=5)]
    request_history[ip].append(now)
    return len(request_history[ip]) > 12

async def handle_attack(prediction, username, ip, db, background_tasks, request):
    """
    Handles the attack by logging it and serving the Deception Portal.
    """
    print(f"ALERT: {prediction} detected from {ip}")
    geo = get_ip_location(ip)
    prev = db.query(AttackLog).order_by(AttackLog.id.desc()).first()
    prev_hash = prev.current_hash if prev else "0"*64
    
    # Log Attack
    db.add(AttackLog(
        ip_address=ip, city=geo['city'], country=geo['country'], 
        isp=geo['isp'], connection_type=geo.get('type','Unknown'), 
        rdns=geo.get('rdns','Unknown'), payload=username, 
        attack_type=prediction, previous_hash=prev_hash, 
        current_hash=calculate_hash(time.time(), username, prev_hash)
    ))
    db.commit()
    
    # Log to Excel in Background
    background_tasks.add_task(log_to_excel, username, prediction, ip, geo['city'], geo['country'], geo['isp'], geo.get('type', 'Unknown'))
    
    time.sleep(random.uniform(0.5, 1.5))
    
    # === RED MARK REMOVAL ===
    # If it's a brute force or SQLi attempt, show the fake portal.
    # We set 'fake_mode' to False so the "Session Monitored" warning is HIDDEN.
    if prediction in ["BruteForce", "SQLi"]:
        return templates.TemplateResponse(
            "internal_portal.html", 
            {
                "request": request, 
                "data": get_fake_data(), 
                "user": username, 
                "fake_mode": False  # <--- CHANGED FROM TRUE TO FALSE
            }
        )
    
    # For other attacks (XSS, RCE), show a login error with a teaser
    return templates.TemplateResponse("login.html", {"request": request, "error": get_genuine_looking_response(prediction, username)})

# --- UNIVERSAL API ENDPOINT ---
@app.post("/api/analyze", response_model=AnalysisResponse)
async def api_analyze_request(req: LoginRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Universal API for external websites to check traffic.
    """
    full_payload = f"{req.username} {req.password}"
    
    # 1. AI Prediction
    prediction = "Normal"
    if model:
        try: prediction = model.predict([full_payload])[0]
        except: pass

    # 2. Logic Overrides
    if "UNION" in full_payload.upper() or "SELECT" in full_payload.upper(): prediction = "SQLi"
    elif "<script>" in full_payload.lower(): prediction = "XSS"
    
    # 3. Handle Normal User
    if prediction == "Normal":
        user = db.query(RealUser).filter(RealUser.username == req.username).first()
        if user and user.password == req.password:
            return {"action": "allow", "risk_score": 0.0, "attack_type": "None", "deception_payload": None}
        else:
             return {"action": "block", "risk_score": 0.3, "attack_type": "AuthFail", "deception_payload": "Invalid Credentials"}
    
    # 4. Handle Attack
    # Log it implicitly for the API context (simplified logging)
    geo = get_ip_location(req.ip_address)
    db.add(AttackLog(ip_address=req.ip_address, payload=req.username, attack_type=prediction, city=geo.get('city', 'Unknown')))
    db.commit()
    
    return {
        "action": "tarpit", 
        "risk_score": 1.0, 
        "attack_type": prediction,
        "deception_payload": "Redirect to Honeypot"
    }

# --- SECURE UPLOAD ENDPOINTS ---
@app.post("/api/admin/upload_file")
async def upload_genuine_file(
    file: UploadFile = File(...), 
    username: str = Form(...), 
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Authenticate
    admin = db.query(RealUser).filter(RealUser.username == username, RealUser.password == password).first()
    if not admin: raise HTTPException(status_code=401, detail="Unauthorized")

    # Save File
    os.makedirs("static/genuine_files", exist_ok=True)
    file_location = f"static/genuine_files/{file.filename}"
    with open(file_location, "wb+") as file_object:
        shutil.copyfileobj(file.file, file_object)

    # Update DB
    new_file = GenuineFile(
        filename=file.filename,
        file_type=file.content_type,
        size=f"{file.size / 1024:.1f} KB",
        upload_date=datetime.now().strftime("%Y-%m-%d"),
        access_level="Admin"
    )
    db.add(new_file)
    db.commit()
    return {"status": "success", "filename": file.filename}

@app.post("/api/admin/update_emails")
async def upload_shadow_db(
    file: UploadFile = File(...), 
    username: str = Form(...), 
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Authenticate
    admin = db.query(RealUser).filter(RealUser.username == username, RealUser.password == password).first()
    if not admin: raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Overwrite Shadow DB CSV
    if not file.filename.endswith('.csv'): return {"error": "Must be a CSV file"}
    
    with open("fake_emails.csv", "wb+") as file_object:
        shutil.copyfileobj(file.file, file_object)
    
    # Reload the data in memory
    load_shadow_db()
    
    return {"status": "success", "message": "Shadow Database Updated"}

# --- STANDARD ROUTES ---
@app.get("/")
def read_root(request: Request): return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, background_tasks: BackgroundTasks, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    client_ip = request.client.host
    full = f"{username} {password}"
    
    # 1. Real User Check
    real_user = db.query(RealUser).filter(RealUser.username == username, RealUser.password == password).first()
    if real_user:
        return templates.TemplateResponse("internal_portal.html", {"request": request, "data": get_genuine_data(), "user": real_user.username, "fake_mode": False})

    # 2. Brute Force
    if username.lower() in ["admin", "root"] and password in ["123", "password", "admin"]:
        return await handle_attack("BruteForce", username, client_ip, db, background_tasks, request)

    # 3. DoS
    if check_rate_limit(client_ip):
        return await handle_attack("DoS", username, client_ip, db, background_tasks, request)

    # 4. AI & Logic Check
    pred = "Normal"
    if not re.match(r"^[a-zA-Z0-9_@.\s-]+$", full):
        if any(x in full.upper() for x in ["UNION", "SELECT", "OR '1'='1"]): pred = "SQLi"
        elif "<script>" in full.lower(): pred = "XSS"
        elif model:
             try: pred = model.predict([full])[0]
             except: pass
    
    if pred != "Normal":
        return await handle_attack(pred, username, client_ip, db, background_tasks, request)

    return templates.TemplateResponse("login.html", {"request": request, "error": "Authentication Failed."})

@app.get("/dashboard")
def dashboard(request: Request): return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/stats")
def get_stats(time_range: str = "all", date: str = None, db: Session = Depends(get_db)):
    query = db.query(AttackLog)
    query = apply_filters(query, time_range, date)
    logs = query.order_by(AttackLog.id.desc()).limit(50).all()
    all_filtered = query.all()
    counts = [0] * 8
    mapping = ["SQLi", "XSS", "Cmdi", "LFI", "RCE", "DoS", "BruteForce", "Scanner"]
    for log in all_filtered:
        if log.attack_type in mapping: counts[mapping.index(log.attack_type)] += 1
    return {"logs": logs, "counts": counts}

@app.get("/download_report")
def download_excel_report(time_range: str = "all", date: str = None, db: Session = Depends(get_db)):
    query = db.query(AttackLog)
    query = apply_filters(query, time_range, date)
    logs = query.all()
    data = [{"ID": l.id, "Time": l.timestamp, "IP": l.ip_address, "City": l.city, "Type": l.attack_type, "Payload": l.payload} for l in logs]
    df = pd.DataFrame(data)
    filename = f"Forensic_Report_{datetime.now().strftime('%Y%m%d')}.xlsx"
    df.to_excel(filename, index=False)
    return FileResponse(path=filename, filename=filename, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')