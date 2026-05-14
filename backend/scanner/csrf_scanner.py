import requests
from bs4 import BeautifulSoup

CSRF_TOKEN_NAMES = {
    "csrf_token",
    "csrfmiddlewaretoken",   # Django
    "_token",                 # Laravel
    "authenticity_token",     # Rails
    "_csrf",                  # Express.js / CSRF npm package
    "__requestverificationtoken",  # ASP.NET (lowercased for comparison)
    "xsrf_token",
    "csrf",
    "token",
    "_csrftoken",
    "csrfkey",
    "anti_csrf_token",
}


SENSITIVE_KEYWORDS = {
    "login", "logout", "transfer", "payment", "pay", "delete",
    "remove", "password", "passwd", "admin", "checkout", "purchase",
    "order", "account", "profile", "settings", "update", "change",
    "reset", "register", "signup", "subscribe", "unsubscribe",
}


CSRF_DESCRIPTION = (
    "Cross-Site Request Forgery (CSRF) tricks authenticated users into "
    "unknowingly submitting requests to a web application they're logged into. "
    "Since browsers automatically include session cookies, a malicious page can "
    "trigger state-changing actions (transfers, password changes, deletions) on "
    "behalf of the victim without their knowledge."
)

CSRF_FIX = """Add a CSRF token to every state-changing form (POST, PUT, DELETE).

✅ Django (built-in — just add the template tag):
    <form method="post">
        {% csrf_token %}
        ...
    </form>

✅ Laravel (built-in — add @csrf directive):
    <form method="POST">
        @csrf
        ...
    </form>

✅ Express.js (use csurf middleware):
    const csrf = require('csurf');
    app.use(csrf());
    // In your template: <input type="hidden" name="_csrf" value="{{ csrfToken }}">

✅ Generic (manual implementation principle):
    # Server: generate a random token, store in session
    import secrets
    session['csrf_token'] = secrets.token_hex(32)

    # Template: embed it in every form
    <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">

    # Server: verify on every POST
    if request.form['csrf_token'] != session['csrf_token']:
        abort(403)"""

SAMESITE_DESCRIPTION = (
    "The session cookie is missing the SameSite attribute. "
    "Without SameSite=Strict or SameSite=Lax, browsers will include "
    "this cookie in cross-origin requests, making CSRF attacks easier to execute."
)

SAMESITE_FIX = """Set the SameSite attribute on all session cookies.

✅ Django (settings.py):
    SESSION_COOKIE_SAMESITE = 'Lax'   # or 'Strict' for maximum protection

✅ Flask:
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

✅ Express.js:
    app.use(session({
        cookie: { sameSite: 'lax' }
    }));

SameSite=Lax  → Blocks cross-site POST requests (recommended default)
SameSite=Strict → Blocks ALL cross-site requests including navigations"""

XFRAME_DESCRIPTION = (
    "The X-Frame-Options header is missing. Without it, attackers can embed "
    "your page inside an invisible iframe and trick users into clicking buttons "
    "they can't see (clickjacking) — a technique often used to facilitate CSRF."
)

XFRAME_FIX = """Add X-Frame-Options to all responses.

✅ Django (settings.py):
    MIDDLEWARE = [..., 'django.middleware.clickjacking.XFrameOptionsMiddleware']
    X_FRAME_OPTIONS = 'DENY'

✅ Flask:
    @app.after_request
    def set_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        return response

✅ Nginx:
    add_header X-Frame-Options "DENY";

DENY        → Page cannot be framed at all (most secure)
SAMEORIGIN  → Page can only be framed by same-origin pages"""

CSP_DESCRIPTION = (
    "The Content-Security-Policy header is missing. CSP acts as a last line of "
    "defence against XSS and some CSRF vectors by restricting which scripts "
    "can execute and which origins can receive requests."
)

CSP_FIX = """Add a Content-Security-Policy header.

✅ Starter policy (safe default):
    Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'

✅ Flask:
    @app.after_request
    def set_csp(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

✅ Django (use django-csp package):
    pip install django-csp
    # settings.py:
    CSP_DEFAULT_SRC = ("'self'",)
    CSP_SCRIPT_SRC = ("'self'",)"""


def is_infrastructure_path(url: str) -> bool:
    
    url_lower = url.lower()
    skip_patterns = ["/cdn-cgi/", "/.well-known/", "/metrics", "/health", "/status"]
    return any(pattern in url_lower for pattern in skip_patterns)


def is_sensitive_url(url: str) -> bool:
    
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in SENSITIVE_KEYWORDS)

def has_csrf_token(form_tag) -> bool:
    
    hidden_inputs = form_tag.find_all("input", {"type": "hidden"})
    for inp in hidden_inputs:
        name = inp.get("name", "").lower()
        if name in CSRF_TOKEN_NAMES:
            return True
    return False

def check_forms(page_url: str, soup: BeautifulSoup) -> list:
    
    findings = []

    for form in soup.find_all("form"):
        raw_method = form.get("method")
        if isinstance(raw_method, str):
            method = raw_method.lower()
        elif isinstance(raw_method, list):
            method = " ".join(str(v) for v in raw_method).lower() if raw_method else "get"
        else:
            method = "get"

        if method != "post":
            continue

        if not has_csrf_token(form):
            raw_action = form.get("action")

            if isinstance(raw_action, str):
                action = raw_action
            elif isinstance(raw_action, list):
                action = " ".join(str(v) for v in raw_action) if raw_action else page_url
            else:
                action = page_url

            severity = "HIGH" if is_sensitive_url(action) else "MEDIUM"

            findings.append({
                "type": "CSRF",
                "severity": severity,
                "url": page_url,
                "parameter": f"form[action={action}]",
                "payload": "N/A (structural check — no injection)",
                "evidence": (
                    f"POST form with action='{action}' has no CSRF token field. "
                    f"Checked for: {', '.join(sorted(CSRF_TOKEN_NAMES)[:5])}..."
                ),
                "description": CSRF_DESCRIPTION,
                "fix": CSRF_FIX,
            })

    return findings


# ── Check 2: Cookie SameSite Attribute ───────────────────────────────────────

def check_cookies(page_url: str, response: requests.Response) -> list:
    
    findings = []

    raw_headers = response.headers.get("Set-Cookie", "")
    if not raw_headers:
        return []

    cookie_headers = response.raw.headers.getlist("Set-Cookie")

    for cookie_header in cookie_headers:
        cookie_lower = cookie_header.lower()

        is_session_cookie = any(
            name in cookie_lower
            for name in ["session", "auth", "token", "sid", "user", "login"]
        )

        if is_session_cookie and "samesite" not in cookie_lower:
            cookie_name = cookie_header.split("=")[0].strip()
            findings.append({
                "type": "CSRF (Missing SameSite Cookie)",
                "severity": "MEDIUM",
                "url": page_url,
                "parameter": f"cookie: {cookie_name}",
                "payload": "N/A (structural check)",
                "evidence": f"Set-Cookie header missing SameSite: {cookie_header[:120]}",
                "description": SAMESITE_DESCRIPTION,
                "fix": SAMESITE_FIX,
            })

    return findings

def check_security_headers(page_url: str, response: requests.Response) -> list:
    
    findings = []
    headers = response.headers

    # Skip infrastructure paths to reduce noise
    if is_infrastructure_path(page_url):
        return []

    # X-Frame-Options
    if "x-frame-options" not in {h.lower() for h in headers}:
        findings.append({
            "type": "Security Header (Missing X-Frame-Options)",
            "severity": "MEDIUM",
            "url": page_url,
            "parameter": "HTTP header: X-Frame-Options",
            "payload": "N/A (structural check)",
            "evidence": "X-Frame-Options header not present in HTTP response.",
            "description": XFRAME_DESCRIPTION,
            "fix": XFRAME_FIX,
        })

    # Content-Security-Policy
    if "content-security-policy" not in {h.lower() for h in headers}:
        findings.append({
            "type": "Security Header (Missing Content-Security-Policy)",
            "severity": "MEDIUM",
            "url": page_url,
            "parameter": "HTTP header: Content-Security-Policy",
            "payload": "N/A (structural check)",
            "evidence": "Content-Security-Policy header not present in HTTP response.",
            "description": CSP_DESCRIPTION,
            "fix": CSP_FIX,
        })

    return findings

def scan_csrf(page_url: str, forms: list, cookies=None) -> list:
    
    findings = []

    try:
        response = requests.get(
            page_url,
            headers={"User-Agent": "Mozilla/5.0 (WebGuard Security Scanner)"},
            timeout=10,
            cookies=cookies,
        )
    except requests.RequestException:
        return []

    soup = BeautifulSoup(response.text, "html.parser")

    findings.extend(check_forms(page_url, soup))
    findings.extend(check_cookies(page_url, response))
    findings.extend(check_security_headers(page_url, response))

    return findings