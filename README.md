# SQL Injection Scanner

A basic SQL injection scanner that discovers HTML forms on a page, sends
crafted payloads to their inputs, and reports forms that appear vulnerable
based on database error messages reflected in the response.

**This project is for educational use and authorized security testing
only.** See [Legal / Ethical Notice](#legal--ethical-notice) below.

## Features

- Crawls and parses `<form>` elements from a target page (or a whole site
  with `--crawl`)
- Sends `"` and `'` payloads to every non-submit input, via GET or POST
  matching the form's method
- Detects common MySQL/MariaDB and MSSQL error signatures reflected in
  responses (error-based detection)
- Built-in DVWA login helper, including setting the security level
- Allowlist gate — refuses to send requests to any host that isn't
  explicitly authorized
- Logs to console and to a log file
- Basic concurrency (multiple forms/pages tested in parallel threads)
- Rate-limiting shared across all threads, to avoid hammering a target

## Requirements

- Python 3.8+
- `requests`
- `beautifulsoup4`

Install dependencies:

```bash
pip install requests beautifulsoup4
# or, if your system blocks global installs:
pip install --break-system-packages requests beautifulsoup4
```

If you're testing with DVWA, you'll also need Docker:

```bash
docker run --rm -p 80:80 vulnerables/web-dvwa
```

Then visit `http://localhost/` (or `http://localhost/DVWA/`, depending on
your image) and run **Create / Reset Database** on `setup.php` before
scanning.

## Usage

```bash
python3 SQL_Inject_Scanner.py <url> [options]
```

### Options

| Flag              | Default         | Description                                      |
|-------------------|-----------------|---------------------------------------------------|
| `--crawl`         | off             | Discover and scan additional same-host pages      |
| `--max-pages N`   | 10              | Max pages to visit when `--crawl` is used          |
| `--workers N`     | 4               | Max concurrent worker threads                      |
| `--rate N`        | 5               | Max requests per second (shared rate limit)        |
| `--log-file PATH` | `sqli_scan.log` | Path to the log file                               |
| `--dvwa`          | off             | Log into DVWA before scanning                      |
| `--dvwa-security` | `low`           | DVWA security level: low / medium / high / impossible |

### Examples

Scan a single page's forms:

```bash
python3 SQL_Inject_Scanner.py http://testphp.vulnweb.com/search.php?test=query
```

Crawl and scan an entire allowed site, with a gentler rate limit:

```bash
python3 SQL_Inject_Scanner.py http://testphp.vulnweb.com/ --crawl --max-pages 8 --rate 2 --workers 2
```

Scan DVWA, forcing the security level and writing to a custom log file:

```bash
python3 SQL_Inject_Scanner.py http://localhost/DVWA/ --dvwa --dvwa-security low --log-file dvwa_scan.log
```

### Reading the output

Each tested form logs one of:

- `VULNERABLE: <url> (payload=..., method=...)` — a payload triggered a
  database error signature in the response
- `No SQLi indicator found: <url> (method=...)` — neither payload
  triggered a known error signature

A summary line is printed at the end:

```
Scan complete: 6 form(s) tested, 1 vulnerable.
```

Full detail (including failed requests and the DVWA login/security flow)
is written to the log file as well as the console.

## Legal / Ethical Notice

Only run this scanner against systems you **own** or are **explicitly
authorized** to test. Scanning third-party systems without permission is
illegal in most jurisdictions, even if the scan doesn't find anything.

The script enforces this with an allowlist (`ALLOWED_HOSTS` at the top of
`SQL_Inject_Scanner.py`) plus automatic allowance for private/local IP
addresses. It will refuse — and log a refusal — before sending any request
to a host that isn't covered by one of these.

Authorized targets used during development of this tool:

- A local DVWA instance (`localhost` / private IPs)
- [testphp.vulnweb.com](http://testphp.vulnweb.com/) — Acunetix's
  permanently-hosted test site, explicitly provided for scanner testing

To add another target you're authorized to test, add its hostname to
`ALLOWED_HOSTS` in the script.

## Known Limitations

- **Detection is error-based only.** It looks for specific DB error
  strings in the response body. It will not catch SQLi that's silent
  (no error shown) or blind/time-based injection.
- **Only `<input>` fields are parsed.** Vulnerable `<select>` or
  `<textarea>` fields are not currently tested.
- Two payload characters only (`"` and `'`) — not a comprehensive
  payload set.
- No CSRF-token handling for target forms beyond DVWA's login/security
  pages specifically.

## Project Files

| File                          | Purpose                                                |
|-------------------------------|---------------------------------------------------------|
| `SQL_Inject_Scanner.py`       | Main scanner — allowlist, logging, concurrency, rate-limiting |
| `README.md`                   | This file                                               |
