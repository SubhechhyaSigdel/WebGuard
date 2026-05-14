from typing import Optional, List
from datetime import datetime
from sqlmodel import Field, Relationship
from .database import SQLModel



class Scan(SQLModel, table=True):

    id: Optional[int] = Field(default=None, primary_key=True)
    target_url: str                          # The URL the user submitted
    status: str = Field(default="pending")   # pending → running → completed / failed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    vulnerabilities: List["Vulnerability"] = Relationship(back_populates="scan")


class Vulnerability(SQLModel, table=True):
    
    id: Optional[int] = Field(default=None, primary_key=True)
    
    scan_id: int = Field(foreign_key="scan.id")
    
    vuln_type: str        # "SQL Injection", "XSS", "CSRF"
    severity: str         # "HIGH", "MEDIUM", "LOW", "INFO"
    affected_url: str     # Which page/endpoint is vulnerable
    parameter: str        # Which input field is vulnerable
    payload: str          # What payload triggered the vulnerability
    evidence: str         # What in the response confirmed it
    description: str      # Plain-language explanation
    fix: str              # How to fix it (with code example)

    # Back-reference to the parent Scan
    scan: Optional[Scan] = Relationship(back_populates="vulnerabilities")