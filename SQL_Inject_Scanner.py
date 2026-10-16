#!/usr/bin/env python3
"""
SQL Injection Scanner
----------------------
Probes web forms for common SQL injection indicators (error-based detection).

ETHICAL / LEGAL NOTICE
-----------------------
Only run this against systems you own or are explicitly authorized to test
(e.g. a local DVWA/bWAPP instance, or a test site that permits it, such as
testphp.vulnweb.com). Scanning third-party systems without permission is
illegal in most places. This script refuses to send requests to any host
that is not in ALLOWED_HOSTS and is not a private/local address.
"""

import argparse
import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

# Hosts/domains explicitly authorized for testing. Add your own
# authorized targets here — do not add a host you don't have
# permission to test.
ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "testphp.vulnweb.com",  # Acunetix's public scanner test site
}

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
)

PAYLOAD_CHARS = "\"'"

ERROR_SIGNATURES = [
    "quoted string is not properly terminated",
    "unclosed quotation mark after the character string",
    "you have an error in your sql syntax",
]

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------


def setup_logger(log_file="sqli_scan.log", level=logging.INFO):
    logger = logging.getLogger("sqli_scanner")
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s")

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    logger.addHandler(console)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger


log = setup_logger()

# ----------------------------------------------------------------------
# Allowlist / ethics gate
# ----------------------------------------------------------------------


def is_private_ip(host):
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def is_allowed_target(url):
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    if hostname in ALLOWED_HOSTS:
        return True
    if is_private_ip(hostname):
        return True
    return False


def require_allowed(url):
    """Raises PermissionError and logs if the target isn't authorized."""
    if not is_allowed_target(url):
        log.error(
            "Refusing to scan %s \u2014 host is not in ALLOWED_HOSTS and is not a "
            "private/local address. Only test systems you own or are explicitly "
            "authorized to test (e.g. a local DVWA instance). Add the host to "
            "ALLOWED_HOSTS at the top of this script if you have authorization.",
            url,
        )
        raise PermissionError(f"Target not authorized: {url}")


# ----------------------------------------------------------------------
# Rate limiting
# ----------------------------------------------------------------------


class RateLimiter:
    """Thread-safe rate limiter: at most `rate` requests per second, shared
    across all threads so concurrency doesn't bypass the limit."""

    def __init__(self, rate=5):
        self.min_interval = 1.0 / rate if rate > 0 else 0
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            sleep_for = self.min_interval - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last_call = time.monotonic()


# ----------------------------------------------------------------------
# HTTP session
# Shared across threads. requests.Session is safe for concurrent
# get()/post() calls from multiple threads (the connection pool handles
# this); we just avoid mutating session-level state like headers after
# startup from multiple threads.
# ----------------------------------------------------------------------

session = requests.Session()
session.headers["User-Agent"] = DEFAULT_USER_AGENT

# ----------------------------------------------------------------------
# Form discovery / parsing
# ----------------------------------------------------------------------


def get_page(url, rate_limiter, timeout=10):
    rate_limiter.wait()
    try:
        resp = session.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp
    except requests.exceptions.RequestException as e:
        log.error("Failed to fetch %s: %s", url, e)
        return None


def get_forms(url, rate_limiter):
    resp = get_page(url, rate_limiter)
    if resp is None:
        return []
    soup = BeautifulSoup(resp.content, "html.parser")
    return soup.find_all("form")


def form_details(form):
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [],
    }
    for input_tag in form.find_all("input"):
        details["inputs"].append(
            {
                "type": input_tag.attrs.get("type", "text"),
                "name": input_tag.attrs.get("name"),
                "value": input_tag.attrs.get("value", ""),
            }
        )
    return details


def vulnerable(response):
    if response is None:
        return False
    body = response.content.decode(errors="replace").lower()
    return any(sig in body for sig in ERROR_SIGNATURES)


# ----------------------------------------------------------------------
# Core scan logic
# ----------------------------------------------------------------------


def test_form(page_url, form, rate_limiter):
    """Send crafted SQLi payloads to a single form. Returns a result dict
    for logging/reporting."""
    details = form_details(form)
    target_url = urljoin(page_url, details["action"]) if details["action"] else page_url

    result = {
        "page": page_url,
        "target_url": target_url,
        "method": details["method"],
        "vulnerable": False,
        "payload": None,
        "error": None,
    }

    for payload_char in PAYLOAD_CHARS:
        data = {}
        for input_tag in details["inputs"]:
            name = input_tag["name"]
            if name is None:
                continue
            if input_tag["type"] == "hidden" or input_tag["value"]:
                data[name] = input_tag["value"] + payload_char
            elif input_tag["type"] != "submit":
                data[name] = f"test{payload_char}"

        rate_limiter.wait()
        try:
            if details["method"] == "post":
                res = session.post(target_url, data=data, timeout=10)
            else:
                res = session.get(target_url, params=data, timeout=10)
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            log.warning("Request failed for %s: %s", target_url, e)
            continue

        if vulnerable(res):
            result["vulnerable"] = True
            result["payload"] = payload_char
            log.warning(
                "VULNERABLE: %s (payload=%r, method=%s)",
                target_url,
                payload_char,
                details["method"],
            )
            break
    else:
        log.info("No SQLi indicator found: %s (method=%s)", target_url, details["method"])

    return result


def scan_page(url, rate_limiter, max_workers=4):
    """Scan every form on a single page, concurrently."""
    require_allowed(url)
    forms = get_forms(url, rate_limiter)
    log.info("Detected %d form(s) on %s", len(forms), url)

    if not forms:
        return []

    results = []
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="form") as executor:
        futures = {executor.submit(test_form, url, form, rate_limiter): form for form in forms}
        for future in as_completed(futures):
            results.append(future.result())

    return results


def discover_links(url, rate_limiter):
    """Find same-host links on a page, for optional site-wide crawling."""
    resp = get_page(url, rate_limiter)
    if resp is None:
        return set()
    soup = BeautifulSoup(resp.content, "html.parser")
    base_host = urlparse(url).hostname
    links = set()
    for a in soup.find_all("a", href=True):
        link = urljoin(url, a["href"]).split("#")[0]
        if link.startswith("http") and urlparse(link).hostname == base_host:
            links.add(link)
    return links


def scan_site(start_url, rate_limiter, max_pages=10, max_workers=4):
    """Crawl same-host pages from start_url and scan each page's forms."""
    require_allowed(start_url)
    visited = set()
    to_visit = {start_url}
    all_results = []

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)

        all_results.extend(scan_page(url, rate_limiter, max_workers=max_workers))

        new_links = discover_links(url, rate_limiter)
        to_visit.update(new_links - visited)

    return all_results


# ----------------------------------------------------------------------
# DVWA login helper (optional, used only with --dvwa)
# ----------------------------------------------------------------------


def dvwa_login(base_url, rate_limiter, username="admin", password="password", security_level="low"):
    """Log into DVWA and set the given security level. Pass security_level=None
    to leave whatever level is currently set untouched."""
    require_allowed(base_url)
    login_url = urljoin(base_url, "login.php")

    resp = get_page(login_url, rate_limiter)
    if resp is None:
        return False
    soup = BeautifulSoup(resp.content, "html.parser")

    token_tag = soup.find("input", {"name": "user_token"})
    if not token_tag:
        log.error("Could not find login CSRF token at %s \u2014 is this actually DVWA?", login_url)
        return False

    data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token_tag.attrs.get("value", ""),
    }
    rate_limiter.wait()
    resp = session.post(login_url, data=data, timeout=10)
    if "login.php" in resp.url:
        log.error("DVWA login failed \u2014 check username/password.")
        return False
    log.info("Logged into DVWA.")

    security_url = urljoin(base_url, "security.php")

    if security_level is not None:
        resp = get_page(security_url, rate_limiter)
        soup = BeautifulSoup(resp.content, "html.parser") if resp else None
        token_tag = soup.find("input", {"name": "user_token"}) if soup else None
        rate_limiter.wait()
        session.post(
            security_url,
            data={
                "security": security_level,
                "seclev_submit": "Submit",
                "user_token": token_tag.attrs.get("value", "") if token_tag else "",
            },
            timeout=10,
        )
    else:
        log.info("Leaving DVWA security level unchanged (not forcing it).")

    verify_resp = get_page(security_url, rate_limiter)
    if verify_resp is not None:
        page_text = BeautifulSoup(verify_resp.content, "html.parser").get_text(" ", strip=True)
        idx = page_text.lower().find("security level is currently")
        if idx != -1:
            end = page_text.find(".", idx)
            snippet = page_text[idx : end + 1] if end != -1 else page_text[idx : idx + 120]
            log.info(snippet)
        else:
            log.warning("Could not confirm security level from page text (continuing anyway).")

    return True


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Basic SQL injection scanner (educational; authorized targets only)."
    )
    parser.add_argument("url", help="http://localhost/DVWA/")
    parser.add_argument("--crawl", action="store_true", help="Discover and scan additional same-host pages")
    parser.add_argument("--max-pages", type=int, default=10, help="Max pages to crawl with --crawl")
    parser.add_argument("--workers", type=int, default=4, help="Max concurrent worker threads")
    parser.add_argument("--rate", type=float, default=5, help="Max requests per second (rate limit)")
    parser.add_argument("--log-file", default="sqli_scan.log", help="Path to the log file")
    parser.add_argument("--dvwa", action="store_true", help="Log into DVWA before scanning")
    parser.add_argument(
        "--dvwa-security",
        default="low",
        choices=["low", "medium", "high", "impossible"],
        help="DVWA security level to set before scanning",
    )
    args = parser.parse_args()

    global log
    log = setup_logger(args.log_file)

    rate_limiter = RateLimiter(args.rate)

    try:
        require_allowed(args.url)
    except PermissionError:
        return

    if args.dvwa:
        base = args.url if args.url.endswith("/") else args.url + "/"
        if not dvwa_login(base, rate_limiter, security_level=args.dvwa_security):
            log.error("Aborting: DVWA login failed.")
            return
        target = urljoin(base, "vulnerabilities/sqli/?id=1&Submit=Submit")
    else:
        target = args.url

    if args.crawl:
        results = scan_site(target, rate_limiter, max_pages=args.max_pages, max_workers=args.workers)
    else:
        results = scan_page(target, rate_limiter, max_workers=args.workers)

    vulnerable_count = sum(1 for r in results if r["vulnerable"])
    log.info("Scan complete: %d form(s) tested, %d vulnerable.", len(results), vulnerable_count)


if __name__ == "__main__":
    main()