import re
from html import escape as html_escape 
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import requests

PAYLOAD_MARKER = "WGXSS_MARKER"

XSS_PAYLOADS = [
    # Classic script tag — blocked by many filters, but still worth trying
    f"<script>alert('{PAYLOAD_MARKER}')</script>",

    # SVG onload — often missed by filters that only look for <script>
    f"<svg onload=alert('{PAYLOAD_MARKER}')>",

    # Image with broken src — triggers onerror when image fails to load
    f"<img src=x onerror=alert('{PAYLOAD_MARKER}')>",

    # Input autofocus — fires when the element receives focus automatically
    f"<input autofocus onfocus=alert('{PAYLOAD_MARKER}')>",

    # Attribute injection — breaks out of an existing HTML attribute
    # e.g. <input value="USER_INPUT"> becomes <input value="" onmouseover="alert('XSS')">
    f'" onmouseover="alert(\'{PAYLOAD_MARKER}\')',

    # Body tag injection
    f"<body onload=alert('{PAYLOAD_MARKER}')>",

    # iframe injection
    f"<iframe src=javascript:alert('{PAYLOAD_MARKER}')>",

    # Uppercase evasion — some filters are case-sensitive
    f"<SCRIPT>alert('{PAYLOAD_MARKER}')</SCRIPT>",
]

COMMON_QUERY_PARAMS = ["q", "search", "id"]

URL_XSS_PAYLOADS = [
    f"<script>alert('{PAYLOAD_MARKER}')</script>",
    f"<svg onload=alert('{PAYLOAD_MARKER}')>",
    f"<img src=x onerror=alert('{PAYLOAD_MARKER}')>",
    f'" onmouseover="alert(\'{PAYLOAD_MARKER}\')',
]

HTML_ENCODING_MAP = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "&": "&amp;",
}

# ── Regex Patterns (fallback) ─────────────────────────────────────────────────
#
# Important: keep these marker-bound to avoid matching harmless inline scripts
# that almost every modern site contains.

XSS_PATTERNS = [
    rf"<script[^>]*>[^<]*{PAYLOAD_MARKER}",
    rf"on\w+\s*=\s*['\"][^'\"]*{PAYLOAD_MARKER}[^'\"]*['\"]",
    rf"javascript\s*:[^\"'\s>]*{PAYLOAD_MARKER}",
    rf"alert\s*\(\s*['\"]{PAYLOAD_MARKER}['\"]",
    rf"{PAYLOAD_MARKER}",
]

# ── Remediation ───────────────────────────────────────────────────────────────

DESCRIPTION = (
    "Cross-Site Scripting (XSS) occurs when user-supplied input is included in "
    "a web page without proper encoding. An attacker can inject malicious JavaScript "
    "that executes in victims' browsers, allowing them to steal session cookies, "
    "capture keystrokes, redirect users to phishing sites, or perform actions on "
    "behalf of the victim."
)

FIX = """Always HTML-encode user input before inserting it into HTML output.
The fix depends on your framework:

❌ Vulnerable (Python):
    return f"<p>Hello, {username}</p>"

✅ Fixed (Python — manual):
    from html import escape
    return f"<p>Hello, {escape(username)}</p>"

✅ Fixed (Jinja2 templates — auto-escaping ON by default):
    <p>Hello, {{ username }}</p>
    # Jinja2 encodes automatically — never use {{ username | safe }} on user input!

✅ Fixed (React — safe by default):
    <p>Hello, {username}</p>
    # React encodes automatically — never use dangerouslySetInnerHTML on user input!

✅ Fixed (Content Security Policy header — defence in depth):
    Content-Security-Policy: default-src 'self'; script-src 'self'
    # Prevents inline scripts even if injection occurs

The root rule: NEVER trust user input. Always encode output."""



def html_encode(payload: str) -> str:
    
    result = payload
    for char, entity in HTML_ENCODING_MAP.items():
        result = result.replace(char, entity)
    return result

def check_reflection(response_text: str, payload: str) -> tuple[bool, str]:
    
    encoded_payload = html_escape(payload, quote=True)

    if encoded_payload in response_text:
        return False, ""

    if payload in response_text:
        # Find the payload in context for the evidence snippet
        idx = response_text.find(payload)
        start = max(0, idx - 40)
        end = min(len(response_text), idx + len(payload) + 40)
        snippet = response_text[start:end].strip()
        return True, f"Payload reflected unencoded: ...{snippet}..."

    if PAYLOAD_MARKER not in response_text:
        return False, ""

    for pattern in XSS_PATTERNS:
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 30)
            end = min(len(response_text), match.end() + 60)
            snippet = response_text[start:end].strip()
            return True, f"XSS pattern matched in response: ...{snippet}..."

    return False, ""

def submit_form(url: str, method: str, data: dict, cookies=None) -> str | None:
    """Submit a form and return the response text, or None on error."""
    headers = {"User-Agent": "Mozilla/5.0 (WebGuard Security Scanner)"}
    try:
        if method == "post":
                resp = requests.post(url, data=data, headers=headers, timeout=10, cookies=cookies)
        else:
            resp = requests.get(url, params=data, headers=headers, timeout=10, cookies=cookies)
        return resp.text
    except requests.RequestException:
        return None

def build_baseline_data(fields: list) -> dict:
    """Same as in sql_scanner — fill form with harmless values."""
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


# ── URL Parameter Testing ─────────────────────────────────────────────────────

def test_url_parameters(page_url: str, cookies=None) -> list:
    
    findings = []
    parsed = urlparse(page_url)
    params = parse_qs(parsed.query)  # e.g. {'q': ['hello'], 'page': ['1']}

    if params:
        candidate_params = {k: (v[0] if v else "test") for k, v in params.items()}
    else:
        candidate_params = {name: "test" for name in COMMON_QUERY_PARAMS}

    headers = {"User-Agent": "Mozilla/5.0 (WebGuard Security Scanner)"}

    for param_name in candidate_params:
        for payload in URL_XSS_PAYLOADS:
            test_params = candidate_params.copy()
            test_params[param_name] = payload

            # Reconstruct the URL with injected parameter
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                resp = requests.get(test_url, headers=headers, timeout=10, cookies=cookies)
                is_vulnerable, evidence = check_reflection(resp.text, payload)

                if is_vulnerable:
                    findings.append({
                        "type": "XSS (Reflected)",
                        "severity": "HIGH",
                        "url": page_url,
                        "parameter": f"URL param: {param_name}",
                        "payload": payload,
                        "evidence": evidence,
                        "description": DESCRIPTION,
                        "fix": FIX,
                    })
                    break  # Found it — move to next parameter

            except requests.RequestException:
                continue

    return findings


# ── Main Scanner ──────────────────────────────────────────────────────────────

def scan_xss(page_url: str, forms: list, cookies=None) -> list:
    
    findings = []

    # ── Test form fields ───────────────────────────────────────────────────
    for form in forms:
        action_url = form["action_url"]
        method = form["method"]
        fields = form["fields"]

        baseline_data = build_baseline_data(fields)

        for field in fields:
            field_name = field["name"]

            for payload in XSS_PAYLOADS:
                # Inject into this field, leave others normal
                injected_data = baseline_data.copy()
                injected_data[field_name] = payload

                response_text = submit_form(action_url, method, injected_data, cookies=cookies)
                if response_text is None:
                    continue

                is_vulnerable, evidence = check_reflection(response_text, payload)

                if is_vulnerable:
                    findings.append({
                        "type": "XSS (Reflected)",
                        "severity": "HIGH",
                        "url": action_url,
                        "parameter": field_name,
                        "payload": payload,
                        "evidence": evidence,
                        "description": DESCRIPTION,
                        "fix": FIX,
                    })
                    break  # One confirmed finding per field is enough

    # ── Test URL parameters ────────────────────────────────────────────────
    url_findings = test_url_parameters(page_url, cookies=cookies)
    findings.extend(url_findings)

    return findings