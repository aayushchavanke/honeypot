from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime

DATABASE_URL = "sqlite:///./chameleon.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AttackLog(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.now)
    ip_address = Column(String)
    city = Column(String, default="Unknown")
    country = Column(String, default="Unknown")
    isp = Column(String, default="Unknown")
    connection_type = Column(String, default="Unknown")
    rdns = Column(String, default="Unknown")
    payload = Column(String)
    attack_type = Column(String)
    previous_hash = Column(String)
    current_hash = Column(String)

class RealUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String) 
    role = Column(String)

class GenuineFile(Base):
    __tablename__ = "company_files"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    file_type = Column(String)
    size = Column(String)
    upload_date = Column(String)
    access_level = Column(String)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()