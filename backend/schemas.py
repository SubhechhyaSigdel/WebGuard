from typing import Optional, List, Dict
from datetime import datetime
from pydantic import BaseModel, HttpUrl


class AuthRequest(BaseModel):
    login_url: HttpUrl
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    method: str = "post"
    extra_fields: Dict[str, str] = {}
    security_url: Optional[HttpUrl] = None
    security_level: Optional[str] = None
    security_field: str = "security"


class ScanRequest(BaseModel):
    url: HttpUrl
    auth: Optional[AuthRequest] = None


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    message: str


class VulnerabilityOut(BaseModel):
    id: int
    vuln_type: str
    severity: str
    affected_url: str
    parameter: str
    payload: str
    evidence: str
    description: str
    fix: str

    class Config:
        from_attributes = True


class ScanResultOut(BaseModel):
    scan_id: int
    target_url: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    vulnerabilities: List[VulnerabilityOut] = []

    class Config:
        from_attributes = True