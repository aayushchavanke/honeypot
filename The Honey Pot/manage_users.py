import getpass
import sys
import os
import shutil
from datetime import datetime
from sqlalchemy.orm import Session
from app.database import engine, SessionLocal, Base, RealUser, GenuineFile

# Helper: Get DB Session
def get_db():
    return SessionLocal()

def init_system():
    print("\n--- 🚀 SYSTEM INITIALIZATION ---")
    if not os.path.exists("static/genuine_files"):
        os.makedirs("static/genuine_files")
        print("[*] Created secure file storage directory.")
    
    Base.metadata.create_all(bind=engine)
    print("[+] Database Synced.")

# --- USER MANAGEMENT ---
def add_user():
    print("\n--- ➕ ADD AUTHORIZED USER ---")
    username = input("Username (e.g. admin@apex.corp): ").strip()
    db = get_db()
    
    if db.query(RealUser).filter(RealUser.username == username).first():
        print(f"[-] Error: {username} already exists.")
        db.close()
        return

    password = getpass.getpass("Password (Hidden): ")
    role = input("Role (e.g. Admin, HR, Manager): ").strip()
    
    new_user = RealUser(username=username, password=password, role=role)
    db.add(new_user)
    db.commit()
    print(f"[+] User {username} added successfully.")
    db.close()

def list_users():
    db = get_db()
    users = db.query(RealUser).all()
    print("\n--- 👥 STAFF DIRECTORY ---")
    print(f"{'ID':<4} {'USERNAME':<30} {'ROLE':<20}")
    print("-" * 60)
    for u in users:
        print(f"{u.id:<4} {u.username:<30} {u.role:<20}")
    print("-" * 60)
    db.close()

def delete_user():
    list_users()
    try:
        uid = int(input("\nEnter ID to delete: "))
        db = get_db()
        u = db.query(RealUser).filter(RealUser.id == uid).first()
        if u:
            db.delete(u)
            db.commit()
            print(f"[+] User {u.username} deleted.")
        else:
            print("[-] User not found.")
        db.close()
    except ValueError: print("Invalid Input")

# --- FILE MANAGEMENT (NEW) ---
def upload_file():
    print("\n--- 📂 UPLOAD GENUINE FILE ---")
    file_path = input("Enter full path to file (e.g. C:/Docs/report.pdf): ").strip().strip('"')
    
    if not os.path.exists(file_path):
        print("[-] Error: File not found.")
        return

    filename = os.path.basename(file_path)
    access_level = input("Access Level (Admin/All): ").strip()
    
    # 1. Copy file to static folder
    dest_folder = "static/genuine_files"
    if not os.path.exists(dest_folder): os.makedirs(dest_folder)
    
    dest_path = os.path.join(dest_folder, filename)
    shutil.copy(file_path, dest_path)
    
    # 2. Get file size
    size_bytes = os.path.getsize(dest_path)
    size_str = f"{size_bytes / 1024:.1f} KB"
    if size_bytes > 1024 * 1024:
        size_str = f"{size_bytes / (1024 * 1024):.1f} MB"

    # 3. Add to Database
    db = get_db()
    new_file = GenuineFile(
        filename=filename,
        file_type=filename.split('.')[-1].upper(),
        size=size_str,
        upload_date=datetime.now().strftime("%Y-%m-%d"),
        access_level=access_level
    )
    db.add(new_file)
    db.commit()
    print(f"[+] File '{filename}' uploaded securely.")
    db.close()

def list_files():
    db = get_db()
    files = db.query(GenuineFile).all()
    print("\n--- 🗂️  SECURE FILES ---")
    print(f"{'ID':<4} {'FILENAME':<35} {'SIZE':<10} {'ACCESS'}")
    print("-" * 65)
    for f in files:
        print(f"{f.id:<4} {f.filename:<35} {f.size:<10} {f.access_level}")
    print("-" * 65)
    db.close()

def delete_file():
    list_files()
    try:
        fid = int(input("\nEnter ID to delete: "))
        db = get_db()
        f = db.query(GenuineFile).filter(GenuineFile.id == fid).first()
        if f:
            # Try to remove actual file
            try:
                os.remove(f"static/genuine_files/{f.filename}")
            except:
                print("[!] Warning: Could not delete actual file from disk.")
            
            db.delete(f)
            db.commit()
            print(f"[+] File record deleted.")
        else:
            print("[-] File not found.")
        db.close()
    except ValueError: print("Invalid Input")

# --- MAIN MENU ---
if __name__ == "__main__":
    init_system()
    while True:
        print("\n=== 🛡️  CHAMELEON ADMIN CONSOLE ===")
        print("1. Add User       2. List Users       3. Delete User")
        print("4. Upload File    5. List Files       6. Delete File")
        print("7. Exit")
        
        c = input("Choice: ")
        if c=='1': add_user()
        elif c=='2': list_users()
        elif c=='3': delete_user()
        elif c=='4': upload_file()
        elif c=='5': list_files()
        elif c=='6': delete_file()
        elif c=='7': break