from pydantic import BaseModel
from typing import Optional

class LoginRequest(BaseModel):
    username: str
    password: str
    ip_address: str
    user_agent: Optional[str] = "Unknown"
    dept_id: Optional[str] = ""
    token: Optional[str] = ""

class AnalysisResponse(BaseModel):
    action: str  # "allow", "block", "tarpit"
    risk_score: float
    attack_type: str
    deception_payload: Optional[str] = None