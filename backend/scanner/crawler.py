import threading
from queue import Queue, Empty
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


MAX_PAGES = 50          # Don't crawl more than this many pages (keeps scans fast)
NUM_THREADS = 5         # Number of parallel worker threads
REQUEST_TIMEOUT = 8     # Seconds to wait for a page before giving up

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".css", ".js", ".pdf", ".zip", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot",
}

def is_same_domain(url: str, base_domain: str) -> bool:
    
    return urlparse(url).netloc == base_domain


def should_skip(url: str) -> bool:
   
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def normalize_url(url: str) -> str:
    
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


def extract_links(soup: BeautifulSoup, current_url: str, base_domain: str) -> list:
    
    links = []
    for tag in soup.find_all('a', href=True):
        href_value = tag.get('href')
        if not href_value:
            continue

        if isinstance(href_value, list):
            if not href_value:
                continue
            href = href_value[0]
        else:
            href = href_value

        if not isinstance(href, str):
            continue

        if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            continue

        absolute_url = urljoin(current_url, href)

        absolute_url = normalize_url(absolute_url)

        if is_same_domain(absolute_url, base_domain) and not should_skip(absolute_url):
            links.append(absolute_url)

    return links


def extract_forms(soup: BeautifulSoup, current_url: str) -> list:
    
    forms = []
    for form in soup.find_all('form'):

        # Get the form's submission URL
        action_value = form.get('action', '')


        if isinstance(action_value, list):
            if not action_value:
                action = ''
            else:
                action = action_value[0]
        else:
            action = action_value

        if not isinstance(action, str):
            action = ''

        action_url = urljoin(current_url, action) if action else current_url

        method_value = form.get('method', 'get')
        if isinstance(method_value, list):
            if not method_value:
                method = 'get'
            else:
                method = str(method_value[0]).lower()
        elif isinstance(method_value, str):
            method = method_value.lower()
        else:
            method = 'get'

        # Find all input fields in this form  
        fields = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            field_name = input_tag.get('name')
            field_type = input_tag.get('type', 'text')

            if field_name and field_type not in ('submit', 'button', 'image', 'reset'):
                fields.append({
                    "name": field_name,
                    "type": field_type,
                })

        if fields:
            forms.append({
                "action_url": action_url,
                "method": method,
                "fields": fields,
            })

    return forms


def crawl(target_url: str, cookies=None) -> list:
    base_domain = urlparse(target_url).netloc

    url_queue = Queue()
    url_queue.put(target_url)

    visited = set()
    visited_lock = threading.Lock()

    results = []
    results_lock = threading.Lock()

    def worker():
        while True:
            try:
                url = url_queue.get(timeout=2)
            except Empty:
                break

            with visited_lock:
                if url in visited:
                    url_queue.task_done()
                    continue

                if len(visited) >= MAX_PAGES:
                    url_queue.task_done()
                    break

                visited.add(url)

            try:
                print(f"[Crawler] Fetching: {url}")
                response = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    headers={"User-Agent": "Mozilla/5.0 (WebGuard Security Scanner)"},
                    cookies=cookies,
                    allow_redirects=True,
                )

                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    url_queue.task_done()
                    continue

            except requests.RequestException as e:
                print(f"[Crawler] Failed to fetch {url}: {e}")
                url_queue.task_done()
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            new_links = extract_links(soup, url, base_domain)
            for link in new_links:
                with visited_lock:
                    if link not in visited:
                        url_queue.put(link)

            forms = extract_forms(soup, url)

            with results_lock:
                results.append({
                    "url": url,
                    "forms": forms,
                })

            url_queue.task_done()

    threads = []
    for i in range(NUM_THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[Crawler] Done. Crawled {len(visited)} pages, found {len(results)} results.")
    return results