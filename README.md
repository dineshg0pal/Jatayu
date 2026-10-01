# Jatayu

Simple web technology fingerprinting tool. One file, pure Python, no dependencies.

## Requirements

- Python 3.7+

## Usage

```bash
python3 jatayu scan https://example.com
```

The `https://` prefix is optional:

```bash
python3 jatayu scan example.com
```

## Options

| Option             | Description |

| `-t`, `--timeout`  | Timeout in seconds (default: 10) |
| `-k`, `--insecure` | Skip TLS certificate verification |
| `--json`           | Output JSON |

## Example output

```
Jatayu 1.0

Target    https://example.com
Status    200 OK
IP        93.184.216.34
Time      0.42s
Title     Example Domain
Server    nginx/1.18.0

Web Server
  nginx 1.18.0

CDN / WAF
  Cloudflare

JavaScript Library
  jQuery 3.6.0

Security Headers  2/6
  + Strict-Transport-Security
  - Content-Security-Policy
  ...
```

## What it detects

Web servers, CDN/WAF, caching, hosting, programming languages, web frameworks, CMS, e-commerce platforms, JavaScript frameworks and libraries, UI frameworks, fonts, analytics, security tools, payment providers, and common security headers.

## Adding signatures

Add one line to the `SIGS` list in `jatayu`:

```python
S("Name", "Category", h={"server": r"name(?:/([\d.]+))?"})
```

Rule keys:

- `h`: response headers
- `m`: meta tags
- `c`: cookie names
- `s`: script and stylesheet URLs
- `b`: page body

The first capture group in a regex is used as the version.

## How it works

Jatayu sends a single GET request and analyses the response headers, cookies, and HTML. It does not crawl, brute-force, or send attack payloads.

## Disclaimer

Use only on websites you own or have permission to test.
