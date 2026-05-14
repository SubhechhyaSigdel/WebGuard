import threading
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
import requests
from bs4 import BeautifulSoup
from requests.cookies import RequestsCookieJar
from sqlmodel import Session

from ..database import SESSION_LOCAL, engine
from ..models import Scan, Vulnerability
from ..schemas import ScanRequest, ScanResponse, ScanResultOut
from ..scanner.crawler import crawl
from ..scanner.sql_scanner import scan_sql_injection
from ..scanner.xss_scanner import scan_xss
from ..scanner.csrf_scanner import scan_csrf

router = APIRouter()
SCAN_TIME_LIMIT_SECONDS = 180


def authenticate_scan_session(auth_request) -> RequestsCookieJar:
    """Log in once and return the authenticated cookies for downstream requests."""
    login_client = requests.Session()
    login_client.headers.update({"User-Agent": "Mozilla/5.0 (WebGuard Security Scanner)"})

    pre_login_response = login_client.get(
        str(auth_request.login_url),
        timeout=15,
        allow_redirects=True,
    )

    if pre_login_response.status_code >= 400:
        raise ValueError(
            f"Failed to load login page with status code {pre_login_response.status_code}"
        )

    hidden_fields = {}
    soup = BeautifulSoup(pre_login_response.text, "html.parser")
    for hidden_input in soup.find_all("input", {"type": "hidden"}):
        name = hidden_input.get("name")
        if not name:
            continue

        value = hidden_input.get("value", "")
        hidden_fields[str(name)] = str(value)

    login_payload = {
        **hidden_fields,
        auth_request.username_field: auth_request.username,
        auth_request.password_field: auth_request.password,
        **auth_request.extra_fields,
    }

    if auth_request.method.lower() == "get":
        response = login_client.get(
            str(auth_request.login_url),
            params=login_payload,
            timeout=15,
            allow_redirects=True,
        )
    else:
        response = login_client.post(
            str(auth_request.login_url),
            data=login_payload,
            timeout=15,
            allow_redirects=True,
        )

    if response.status_code >= 400:
        raise ValueError(f"Login failed with status code {response.status_code}")

    if auth_request.security_url and auth_request.security_level:
        security_page = login_client.get(
            str(auth_request.security_url),
            timeout=15,
            allow_redirects=True,
        )

        if security_page.status_code >= 400:
            raise ValueError(
                f"Failed to load security page with status code {security_page.status_code}"
            )

        security_payload = {
            auth_request.security_field: auth_request.security_level,
        }

        security_soup = BeautifulSoup(security_page.text, "html.parser")
        for hidden_input in security_soup.find_all("input", {"type": "hidden"}):
            name = hidden_input.get("name")
            if not name:
                continue
            value = hidden_input.get("value", "")
            security_payload[str(name)] = str(value)

        security_payload.setdefault("seclev_submit", "Submit")

        security_response = login_client.post(
            str(auth_request.security_url),
            data=security_payload,
            timeout=15,
            allow_redirects=True,
        )

        if security_response.status_code >= 400:
            raise ValueError(
                f"Failed to set security level with status code {security_response.status_code}"
            )

    return login_client.cookies.copy()


def run_scan(scan_id: int, target_url: str, auth_request=None):
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            print(f"[WebGuard] Scan {scan_id} not found")
            return

        scan.status = "running"
        session.add(scan)
        session.commit()

        try:
            cookies = None
            if auth_request is not None:
                print(f"[WebGuard] Authenticating scan session for {target_url}")
                cookies = authenticate_scan_session(auth_request)

            print(f"[WebGuard] Starting crawl for {target_url}")
            crawl_results = crawl(target_url, cookies=cookies)

            all_vulnerabilities = []
            scan_started_at = datetime.utcnow()

            
            for page in crawl_results:
                elapsed = (datetime.utcnow() - scan_started_at).total_seconds()
                if elapsed > SCAN_TIME_LIMIT_SECONDS:
                    print(
                        f"[WebGuard] Scan {scan_id} reached time limit "
                        f"({SCAN_TIME_LIMIT_SECONDS}s). Returning partial results."
                    )
                    break

                page_url = page["url"]
                forms = page["forms"]

                sql_findings = scan_sql_injection(page_url, forms, cookies=cookies)
                xss_findings = scan_xss(page_url, forms, cookies=cookies)
                csrf_findings = scan_csrf(page_url, forms, cookies=cookies)

                all_vulnerabilities.extend(sql_findings)
                all_vulnerabilities.extend(xss_findings)
                all_vulnerabilities.extend(csrf_findings)

           
            seen_headers = set()
            deduplicated = []
            for finding in all_vulnerabilities:
                finding_type = finding["type"]
                # Only deduplicate Security Header findings
                if finding_type.startswith("Security Header"):
                    key = (finding_type, finding["parameter"])
                    if key in seen_headers:
                        continue
                    seen_headers.add(key)
                deduplicated.append(finding)
            all_vulnerabilities = deduplicated

            
            for finding in all_vulnerabilities:
                vuln = Vulnerability(
                    scan_id=scan_id,
                    vuln_type=finding["type"],
                    severity=finding["severity"],
                    affected_url=finding["url"],
                    parameter=finding["parameter"],
                    payload=finding["payload"],
                    evidence=finding["evidence"],
                    description=finding["description"],
                    fix=finding["fix"],
                )
                session.add(vuln)

            
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()

        except Exception as e:
            # If anything goes wrong, mark it as failed
            print(f"[WebGuard] Scan failed: {e}")
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()

        session.add(scan)
        session.commit()



@router.post("/scan", response_model=ScanResponse)
def start_scan(request: ScanRequest, session: SESSION_LOCAL):
    
    scan = Scan(target_url=str(request.url))
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # Launch the scan in a background thread
    # daemon=True means the thread won't prevent the server from shutting down
    thread = threading.Thread(
        target=run_scan,
        args=(scan.id, str(request.url), request.auth),
        daemon=True
    )
    thread.start()

    return ScanResponse(
        scan_id=scan.id, # type: ignore
        status="pending",
        message=f"Scan started. Poll GET /api/scan/{scan.id} for results."
    )


@router.get("/scan/{scan_id}", response_model=ScanResultOut)
def get_scan_result(scan_id: int, session: SESSION_LOCAL):
    """
    Endpoint 2: Get scan results by ID.
    
    The frontend polls this every 3 seconds until status = "completed".
    """
    scan = session.get(Scan, scan_id)

    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan {scan_id} not found")

    return ScanResultOut(
        scan_id=scan.id, 
        target_url=scan.target_url,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        vulnerabilities=scan.vulnerabilities, 
    )