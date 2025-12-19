import hashlib
import pandas as pd
import requests
import socket
import os
import random
from faker import Faker
# We import the DB models to fetch REAL data for the genuine user
from .database import SessionLocal, RealUser, GenuineFile

fake = Faker()
SHADOW_DB = None

# --- INITIALIZATION ---
def load_shadow_db():
    global SHADOW_DB
    try:
        if os.path.exists("fake_emails.csv"):
            SHADOW_DB = pd.read_csv("fake_emails.csv")
            # Ensure date is string
            SHADOW_DB['date'] = SHADOW_DB['date'].astype(str)
        else:
            SHADOW_DB = pd.DataFrame()
    except:
        SHADOW_DB = pd.DataFrame()

load_shadow_db()

def calculate_hash(timestamp, payload, previous_hash):
    block_string = f"{timestamp}-{payload}-{previous_hash}"
    return hashlib.sha256(block_string.encode()).hexdigest()

def get_ip_location(ip_address):
    intel = {"city": "Internal", "country": "Local", "isp": "Loopback", "type": "Localhost", "rdns": "localhost"}
    if ip_address in ["127.0.0.1", "localhost", "::1"]: return intel
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp,org,as", timeout=2)
        data = response.json()
        if data['status'] == 'success':
            intel["city"] = data.get('city', 'Unknown')
            intel["country"] = data.get('country', 'Unknown')
            intel["isp"] = data.get('isp', 'Unknown')
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                intel["rdns"] = hostname
            except: intel["rdns"] = "No PTR"
            
            isp_lower = (data.get('isp','') + data.get('org','')).lower()
            if "tor" in isp_lower: intel["type"] = "TOR EXIT NODE"
            elif any(x in isp_lower for x in ["vpn", "hosting", "cloud"]): intel["type"] = "VPN / DATA CENTER"
            else: intel["type"] = "RESIDENTIAL"
    except: pass
    return intel

# --- PORTAL DATA GENERATORS ---

def get_genuine_data():
    """
    Returns REAL data from your secure database for legitimate admins.
    """
    db = SessionLocal()
    
    # 1. Real Staff List
    real_users = db.query(RealUser).all()
    staff = [{"name": u.username.split('@')[0].replace('.', ' ').title(), "role": u.role, "email": u.username, "status": "Active"} for u in real_users]
    
    # 2. Real Files
    real_files = db.query(GenuineFile).all()
    files = [{"name": f.filename, "type": f.file_type, "size": f.size, "date": f.upload_date} for f in real_files]
    
    # 3. Genuine Emails (Fixed set from top of CSV to simulate stability)
    emails = []
    if SHADOW_DB is not None and not SHADOW_DB.empty:
        emails = SHADOW_DB.head(5).to_dict(orient="records")
    
    db.close()
    return {"emails": emails, "files": files, "staff": staff}

def get_fake_data():
    """
    Returns RANDOMIZED fake data for hackers (Honeypot Mode).
    """
    # 1. Random Fake Emails (14 to 25 rows)
    emails = []
    if SHADOW_DB is not None and not SHADOW_DB.empty:
        count = random.randint(14, 25)
        emails = SHADOW_DB.sample(n=min(count, len(SHADOW_DB))).to_dict(orient="records")
    
    # 2. Fake Files
    files = []
    file_types = ['pdf', 'docx', 'sql', 'bak', 'zip']
    for _ in range(random.randint(6, 12)):
        files.append({
            "name": f"{fake.word().capitalize()}_{fake.word().capitalize()}.{random.choice(file_types)}",
            "type": "Confidential",
            "size": f"{random.randint(10, 900)} MB",
            "date": fake.date_this_year().strftime("%Y-%m-%d")
        })
    
    # 3. Fake Staff
    staff = []
    for _ in range(random.randint(10, 20)):
        staff.append({
            "name": fake.name(),
            "role": fake.job(),
            "email": fake.company_email(),
            "status": random.choice(["Active", "Suspended", "On Leave"])
        })
    
    return {"emails": emails, "files": files, "staff": staff}

# Compatibility function to prevent ImportError in main.py
def get_fake_dashboard_html():
    return get_fake_data() 
def get_genuine_emails():
    return get_genuine_data()['emails']
def get_fake_emails():
    return get_fake_data()['emails']


# --- DECEPTION HTML SNIPPETS (For Login Page Traps) ---

def get_genuine_looking_response(attack_type, payload):
    
    if attack_type == "Cmdi":
        return f"""<div class="bg-dark p-3 text-white font-monospace rounded shadow-lg"><div class="text-success mb-2">root@server:~# {payload}</div><div class="text-light opacity-75">drwx------ 4 root root .ssh<br>-rw------- 1 root root id_rsa</div><div class="mt-2 text-success">root@server:~# <span class="blink">_</span></div></div><style>.blink{{animation:b 1s infinite}}@keyframes b{{50%{{opacity:0}}}}</style>"""

    elif attack_type == "LFI":
        return f"""<div class="card bg-light border-warning"><div class="card-header bg-warning text-dark fw-bold"><i class="fas fa-file-alt"></i> CONFIG PREVIEW</div><div class="card-body font-monospace small"><p><strong>File:</strong> {payload}</p><div class="bg-white p-2 border"><pre class="m-0">DB_HOST=10.0.0.55\nDB_USER=root\nDB_PASS=S3cur3!</pre></div></div></div>"""

    elif attack_type == "RCE":
        return f"""<div class="bg-black p-3 font-monospace text-success border-start border-5 border-success"><div>>>> {payload}</div><div>uid=0(root) gid=0(root)</div></div>"""

    elif attack_type == "XSS":
        # Includes "DEBUGGER" so the Red Team Console recognizes success
        return f"""<div class="alert alert-info border-info text-dark"><h5><i class="fas fa-search"></i> DEBUGGER</h5><p>Reflected Input:</p><code class="bg-white px-2 py-1 border">{payload}</code></div>"""

    elif attack_type == "DoS":
        return f"""<div class="bg-dark p-4 text-danger text-center font-monospace border border-danger"><h1>KERNEL PANIC</h1><p>STACK OVERFLOW</p></div>"""

    return "Authentication Failed."