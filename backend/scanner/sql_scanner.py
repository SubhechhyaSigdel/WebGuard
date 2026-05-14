import re
import time
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import requests


SQL_PAYLOADS = [
    # Tautology payloads
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "' OR 'x'='x",
    "1 OR 1=1",

    # Quote-based error triggers
    "'",
    "''",
    "`",

    # UNION probes
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",

    # Boolean blind
    "' AND 1=1 --",
    "' AND 1=2 --",

    # Time-based blind (MySQL / MariaDB)
    "' AND SLEEP(3) --",
    "'; WAITFOR DELAY '0:0:3' --",   # MSSQL equivalent
]

DB_ERROR_PATTERNS = [
    # MySQL / MariaDB
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",

    # Microsoft SQL Server
    r"unclosed quotation mark after the character string",
    r"incorrect syntax near",
    r"microsoft.*odbc.*sql server",
    r"mssql_query\(\)",

    # Oracle
    r"ora-\d{4,5}",
    r"oracle.*driver",
    r"quoted string not properly terminated",

    # PostgreSQL
    r"postgresql.*error",
    r"pg_query\(\)",
    r"unterminated quoted string at or near",

    # SQLite
    r"sqlite.*exception",
    r"sqlite3\.operationalerror",

    # Generic
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"db2 sql error",
]

COMMON_QUERY_PARAMS = ["id", "q", "search"]

# Focused subset for URL parameter probes to keep scans practical on large sites.
URL_SQL_PAYLOADS = [
    "'",
    "' OR 1=1 --",
    "' AND 1=2 --",
    "' UNION SELECT NULL --",
    "' AND SLEEP(3) --",
]

BOOLEAN_TRUE_PAYLOAD = "' AND 1=1 --"
BOOLEAN_FALSE_PAYLOAD = "' AND 1=2 --"

DESCRIPTION = (
    "SQL Injection allows an attacker to manipulate the SQL queries your application "
    "sends to the database. By injecting crafted input into form fields or URL parameters, "
    "an attacker can bypass authentication, read all data in the database, modify or delete "
    "records, and in some configurations execute OS commands on the server."
)

FIX = """Use parameterized queries (prepared statements) — NEVER build SQL strings by concatenating user input.

❌ Vulnerable (Python):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

✅ Fixed (Python with psycopg2 / SQLModel):
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))

✅ Fixed (SQLModel ORM — safest approach):
    user = session.exec(select(User).where(User.username == username)).first()

The key principle: keep SQL code and user data completely separate.
The database driver handles escaping automatically when you use placeholders."""


# ── Helper: Build a baseline form submission ──────────────────────────────────

def build_baseline_data(fields: list) -> dict:
    
    data = {}
    for field in fields:
        field_type = field.get("type", "text")
        if field_type == "email":
            data[field["name"]] = "test@example.com"
        elif field_type == "number":
            data[field["name"]] = "1"
        elif field_type == "password":
            data[field["name"]] = "TestPassword123"
        else:
            data[field["name"]] = "testvalue"
    return data


# ── Helper: Submit a form ─────────────────────────────────────────────────────

def submit_form(url: str, method: str, data: dict, cookies=None) -> tuple:
    
    headers = {"User-Agent": "Mozilla/5.0 (WebGuard Security Scanner)"}
    try:
        start = time.time()
        if method == "post":
            resp = requests.post(url, data=data, headers=headers, timeout=15, cookies=cookies)
        else:
            resp = requests.get(url, params=data, headers=headers, timeout=15, cookies=cookies)
        elapsed = time.time() - start
        return resp.text, resp.status_code, elapsed
    except requests.RequestException:
        return None, None, None


# ── Method A: Pattern Matching ────────────────────────────────────────────────

def check_error_patterns(response_text: str) -> str | None:
    
    for pattern in DB_ERROR_PATTERNS:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 30)
            end = min(len(response_text), match.end() + 60)
            return response_text[start:end].strip()
    return None

def check_response_diff(baseline_text: str, injected_text: str) -> bool:
    
    baseline_len = len(baseline_text)
    diff = abs(len(injected_text) - baseline_len)

    threshold = max(200, int(baseline_len * 0.30))
    return diff > threshold


# ── Method C: Time-Based Detection ───────────────────────────────────────────

def check_timing(baseline_elapsed: float, injected_elapsed: float) -> bool:
    
    return (injected_elapsed - baseline_elapsed) >= 2.5


def is_meaningful_response_change(
    baseline_text: str,
    baseline_status: int,
    injected_text: str,
    injected_status: int,
) -> bool:
    
    if injected_status != baseline_status:
        return True
    return check_response_diff(baseline_text, injected_text)


def request_url(test_url: str, cookies=None) -> tuple:
   
    headers = {"User-Agent": "Mozilla/5.0 (WebGuard Security Scanner)"}
    try:
        start = time.time()
        resp = requests.get(test_url, headers=headers, timeout=15, cookies=cookies)
        elapsed = time.time() - start
        return resp.text, resp.status_code, elapsed
    except requests.RequestException:
        return None, None, None


def text_similarity(a: str, b: str) -> float:
    """Return similarity ratio in [0,1] for two response bodies."""
    return SequenceMatcher(None, a, b).ratio()


def detect_boolean_blind(
    baseline_text: str,
    baseline_status: int,
    true_text: str,
    true_status: int,
    false_text: str,
    false_status: int,
) -> tuple[bool, str]:
    
    sim_true = text_similarity(baseline_text, true_text)
    sim_false = text_similarity(baseline_text, false_text)

    status_signal = (baseline_status == true_status) and (false_status != true_status)
    content_signal = (sim_true >= 0.94) and ((sim_true - sim_false) >= 0.08)

    if status_signal or content_signal:
        return (
            True,
            (
                f"Boolean-differential behavior detected: "
                f"status baseline/true/false={baseline_status}/{true_status}/{false_status}, "
                f"similarity baseline~true={sim_true:.3f}, baseline~false={sim_false:.3f}."
            ),
        )

    return False, ""


def test_url_parameters(page_url: str, cookies=None) -> list:
    
    findings = []
    parsed = urlparse(page_url)
    params = parse_qs(parsed.query)

    if params:
        candidate_params = {k: (v[0] if v else "1") for k, v in params.items()}
    else:
        candidate_params = {name: "1" for name in COMMON_QUERY_PARAMS}

    baseline_query = urlencode(candidate_params)
    baseline_url = urlunparse(parsed._replace(query=baseline_query))
    baseline_text, baseline_status, baseline_elapsed = request_url(baseline_url, cookies=cookies)

    if baseline_text is None:
        return []

    for param_name in candidate_params:
        # Boolean-blind probe first: fast signal when errors are hidden.
        true_params = candidate_params.copy()
        true_params[param_name] = BOOLEAN_TRUE_PAYLOAD
        true_url = urlunparse(parsed._replace(query=urlencode(true_params)))
        true_text, true_status, _ = request_url(true_url, cookies=cookies)

        false_params = candidate_params.copy()
        false_params[param_name] = BOOLEAN_FALSE_PAYLOAD
        false_url = urlunparse(parsed._replace(query=urlencode(false_params)))
        false_text, false_status, _ = request_url(false_url, cookies=cookies)

        if true_text is not None and false_text is not None:
            is_boolean_sqli, evidence = detect_boolean_blind(
                baseline_text,
                baseline_status,
                true_text,
                true_status,
                false_text,
                false_status,
            )
            if is_boolean_sqli:
                findings.append({
                    "type": "SQL Injection (Boolean-Based Blind)",
                    "severity": "HIGH",
                    "url": baseline_url,
                    "parameter": f"URL param: {param_name}",
                    "payload": f"{BOOLEAN_TRUE_PAYLOAD} / {BOOLEAN_FALSE_PAYLOAD}",
                    "evidence": evidence,
                    "description": DESCRIPTION,
                    "fix": FIX,
                })
                continue

        for payload in URL_SQL_PAYLOADS:
            test_params = candidate_params.copy()
            test_params[param_name] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            injected_text, injected_status, injected_elapsed = request_url(test_url, cookies=cookies)
            if injected_text is None:
                continue

            evidence = check_error_patterns(injected_text)
            if evidence:
                findings.append({
                    "type": "SQL Injection",
                    "severity": "HIGH",
                    "url": baseline_url,
                    "parameter": f"URL param: {param_name}",
                    "payload": payload,
                    "evidence": f"Database error in response: ...{evidence}...",
                    "description": DESCRIPTION,
                    "fix": FIX,
                })
                break

            if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                if check_timing(baseline_elapsed, injected_elapsed):
                    findings.append({
                        "type": "SQL Injection (Time-Based Blind)",
                        "severity": "HIGH",
                        "url": baseline_url,
                        "parameter": f"URL param: {param_name}",
                        "payload": payload,
                        "evidence": (
                            f"Response delayed by {injected_elapsed - baseline_elapsed:.1f}s "
                            f"(baseline: {baseline_elapsed:.2f}s, "
                            f"injected: {injected_elapsed:.2f}s). "
                            f"Payload appears to have affected backend execution."
                        ),
                        "description": DESCRIPTION,
                        "fix": FIX,
                    })
                    break

            if is_meaningful_response_change(
                baseline_text,
                baseline_status,
                injected_text,
                injected_status,
            ):
                findings.append({
                    "type": "SQL Injection (Suspected)",
                    "severity": "MEDIUM",
                    "url": baseline_url,
                    "parameter": f"URL param: {param_name}",
                    "payload": payload,
                    "evidence": (
                        f"Meaningful response difference detected for injected URL parameter. "
                        f"Baseline status={baseline_status}, injected status={injected_status}, "
                        f"baseline_len={len(baseline_text)}, injected_len={len(injected_text)}."
                    ),
                    "description": DESCRIPTION,
                    "fix": FIX,
                })
                break

    return findings

def scan_sql_injection(page_url: str, forms: list, cookies=None) -> list:
    
    findings = []

    for form in forms:
        action_url = form["action_url"]
        method = form["method"]
        fields = form["fields"]

        # ── Step 1: Get baseline ───────────────────────────────────────────
        baseline_data = build_baseline_data(fields)
        baseline_text, baseline_status, baseline_elapsed = submit_form(
            action_url, method, baseline_data, cookies=cookies
        )

        if baseline_text is None:
            continue

       
        for field in fields:
            field_name = field["name"]

            # Boolean-blind probe first: catches cases where errors are suppressed.
            true_data = baseline_data.copy()
            true_data[field_name] = BOOLEAN_TRUE_PAYLOAD
            true_text, true_status, _ = submit_form(
                action_url,
                method,
                true_data,
                cookies=cookies,
            )

            false_data = baseline_data.copy()
            false_data[field_name] = BOOLEAN_FALSE_PAYLOAD
            false_text, false_status, _ = submit_form(
                action_url,
                method,
                false_data,
                cookies=cookies,
            )

            if true_text is not None and false_text is not None:
                is_boolean_sqli, evidence = detect_boolean_blind(
                    baseline_text,
                    baseline_status,
                    true_text,
                    true_status,
                    false_text,
                    false_status,
                )
                if is_boolean_sqli:
                    findings.append({
                        "type": "SQL Injection (Boolean-Based Blind)",
                        "severity": "HIGH",
                        "url": action_url,
                        "parameter": field_name,
                        "payload": f"{BOOLEAN_TRUE_PAYLOAD} / {BOOLEAN_FALSE_PAYLOAD}",
                        "evidence": evidence,
                        "description": DESCRIPTION,
                        "fix": FIX,
                    })
                    continue

            for payload in SQL_PAYLOADS:

                injected_data = baseline_data.copy()
                injected_data[field_name] = payload

                injected_text, injected_status, injected_elapsed = submit_form(
                    action_url, method, injected_data, cookies=cookies
                )

                if injected_text is None:
                    continue

              
                evidence = check_error_patterns(injected_text)
                if evidence:
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "HIGH",
                        "url": action_url,
                        "parameter": field_name,
                        "payload": payload,
                        "evidence": f"Database error in response: ...{evidence}...",
                        "description": DESCRIPTION,
                        "fix": FIX,
                    })
                    
                    break

            
                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                    if check_timing(baseline_elapsed, injected_elapsed):
                        findings.append({
                            "type": "SQL Injection (Time-Based Blind)",
                            "severity": "HIGH",
                            "url": action_url,
                            "parameter": field_name,
                            "payload": payload,
                            "evidence": (
                                f"Response delayed by {injected_elapsed - baseline_elapsed:.1f}s "
                                f"(baseline: {baseline_elapsed:.2f}s, "
                                f"injected: {injected_elapsed:.2f}s). "
                                f"SLEEP() was executed by the database."
                            ),
                            "description": DESCRIPTION,
                            "fix": FIX,
                        })
                        break

            
                if is_meaningful_response_change(
                    baseline_text,
                    baseline_status,
                    injected_text,
                    injected_status,
                ):
                    findings.append({
                        "type": "SQL Injection (Suspected)",
                        "severity": "MEDIUM",
                        "url": action_url,
                        "parameter": field_name,
                        "payload": payload,
                        "evidence": (
                            f"Response length changed significantly: "
                            f"baseline={len(baseline_text)} chars, "
                            f"injected={len(injected_text)} chars "
                            f"(diff={abs(len(injected_text) - len(baseline_text))})."
                        ),
                        "description": DESCRIPTION,
                        "fix": FIX,
                    })
                    break  

    findings.extend(test_url_parameters(page_url, cookies=cookies))
    return findings