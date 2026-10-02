
#!/usr/bin/env python3
"""Jatayu 1.2 - Web technology fingerprinting.

Usage:
  python3 jatayu.py scan https://example.com
  python3 jatayu.py scan https://example.com --json
  python3 jatayu.py scan https://example.com --vuln-check
"""
import argparse
import json
import re
import socket
import ssl
import sys
import time
import zlib
from html.parser import HTMLParser
from http.client import HTTPException, IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urljoin, urlencode
from urllib.request import Request, urlopen

VERSION = "1.2"
UA = "Mozilla/5.0 (compatible; Jatayu/1.2)"
MAX_BYTES = 2_000_000
MAX_ASSET_BYTES = 350_000
MAX_ASSETS = 20

SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

ORDER = [
    "Web Server", "CDN / WAF", "Hosting", "Caching",
    "Programming Language", "Web Framework", "CMS",
    "E-commerce", "JavaScript Framework", "JavaScript Library",
    "UI Framework", "Fonts & Icons", "Analytics",
    "Security", "Payment", "Database", "Other"
]


def load_signatures():
    try:
        with open("technologies.txt", "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        sys.exit("jatayu: technologies.txt not found in current directory")
    except json.JSONDecodeError as e:
        sys.exit(f"jatayu: invalid technologies.txt: {e}")

    if not isinstance(data, list):
        sys.exit("jatayu: technologies.txt must contain a JSON list")

    for item in data:
        if not isinstance(item, dict) or not item.get("name") or not item.get("category"):
            sys.exit("jatayu: invalid technology entry (name/category required)")
        for key in ("headers", "meta", "cookies"):
            if key in item and not isinstance(item[key], dict):
                sys.exit(f"jatayu: {item['name']}: {key} must be an object")
        for key in ("body", "assets", "asset_content"):
            if key in item and not isinstance(item[key], list):
                sys.exit(f"jatayu: {item['name']}: {key} must be a list")
    return data


def read_body(resp, limit=MAX_BYTES):
    chunks = []
    size = 0
    try:
        while size < limit:
            chunk = resp.read(min(65536, limit - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except IncompleteRead as e:
        chunks.append(e.partial)
    except (OSError, HTTPException):
        if not chunks:
            raise
    return b"".join(chunks)


def fetch(url, timeout, verify=True, limit=MAX_BYTES):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Encoding": "gzip, identity"
    })

    start = time.time()
    try:
        resp = urlopen(req, timeout=timeout, context=ctx)
    except HTTPError as e:
        resp = e

    body = read_body(resp, limit)
    elapsed = time.time() - start

    if resp.headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            body = zlib.decompressobj(
                16 + zlib.MAX_WBITS
            ).decompress(body)
        except zlib.error:
            pass

    headers = {}
    for k, v in resp.headers.items():
        k = k.lower()
        headers[k] = headers[k] + ", " + v if k in headers else v

    cookies = [
        c.split("=", 1)[0].strip()
        for c in (resp.headers.get_all("Set-Cookie") or [])
    ]

    try:
        html = body.decode(
            resp.headers.get_content_charset() or "utf-8", "replace"
        )
    except LookupError:
        html = body.decode("utf-8", "replace")

    return {
        "final": resp.geturl(),
        "status": getattr(resp, "status", None) or getattr(resp, "code", 0),
        "reason": getattr(resp, "reason", "") or "",
        "headers": headers,
        "cookies": cookies,
        "html": html,
        "time": elapsed
    }


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.metas = {}
        self.assets = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        tag = tag.lower()

        if tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name and a.get("content") is not None:
                self.metas[name] = a["content"]

        if tag == "script" and a.get("src"):
            self.assets.append(a["src"])

        if tag == "link" and a.get("href"):
            rel = (a.get("rel") or "").lower()
            if any(x in rel for x in (
                "stylesheet", "preload", "modulepreload", "icon"
            )):
                self.assets.append(a["href"])

        if tag == "a" and a.get("href"):
            self.links.append(a["href"])


def same_origin(a, b):
    x, y = urlparse(a), urlparse(b)
    def port(u):
        return u.port or (443 if u.scheme == "https" else 80)
    return (
        x.scheme in ("http", "https")
        and y.scheme in ("http", "https")
        and x.hostname == y.hostname
        and port(x) == port(y)
    )


def inspect_assets(page, timeout, verify):
    parser = PageParser()
    parser.feed(page["html"])

    assets = []
    for raw in parser.assets:
        url = urljoin(page["final"], raw)
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            continue
        if not same_origin(page["final"], url):
            continue
        if not p.path.lower().endswith((".js", ".css")):
            continue
        if url not in assets:
            assets.append(url)

    contents = []
    for url in assets[:MAX_ASSETS]:
        try:
            result = fetch(
                url, timeout, verify=verify, limit=MAX_ASSET_BYTES
            )
            contents.append({
                "url": url,
                "content": result["html"].lower()
            })
        except Exception:
            continue

    return parser, assets, contents


def detect(page, signatures, timeout=10, verify=True):
    parser, assets, asset_contents = inspect_assets(
        page, timeout, verify
    )

    headers = page["headers"]
    cookies = page["cookies"]
    body = page["html"].lower()
    asset_urls = "\n".join(assets).lower()

    found = {}

    for sig in signatures:
        name = sig["name"]
        evidence = []
        versions = []

        # HTTP response headers
        for key, pattern in sig.get("headers", {}).items():
            value = headers.get(key.lower(), "")
            if value and re.search(pattern, value, re.I):
                evidence.append({
                    "source": "header",
                    "detail": f"{key}: {value[:180]}"
                })
                if sig.get("version_header", "").lower() == key.lower():
                    m = re.search(r"\d+(?:\.\d+)+", value)
                    if m:
                        versions.append(m.group(0))

        # Meta tags
        for key, pattern in sig.get("meta", {}).items():
            value = parser.metas.get(key.lower(), "")
            if value and re.search(pattern, value, re.I):
                evidence.append({
                    "source": "meta",
                    "detail": f"{key}: {value[:180]}"
                })
                m = re.search(r"\d+(?:\.\d+)+", value)
                if m:
                    versions.append(m.group(0))

        # Cookies: match cookie names, not cookie values
        for key, pattern in sig.get("cookies", {}).items():
            for cookie in cookies:
                if cookie.lower() == key.lower():
                    evidence.append({
                        "source": "cookie",
                        "detail": cookie
                    })

        # HTML patterns
        for pattern in sig.get("body", []):
            if pattern.lower() in body:
                evidence.append({
                    "source": "html",
                    "detail": f"Matched: {pattern}"
                })

        # Asset URL patterns
        for pattern in sig.get("assets", []):
            matches = [
                a for a in assets
                if pattern.lower() in a.lower()
            ]
            if matches:
                evidence.append({
                    "source": "asset_url",
                    "detail": matches[0][:220]
                })
                m = re.search(r"\d+\.\d+(?:\.\d+)?", matches[0])
                if m:
                    versions.append(m.group(0))

        # Asset content patterns
        for pattern in sig.get("asset_content", []):
            for asset in asset_contents:
                if pattern.lower() in asset["content"]:
                    evidence.append({
                        "source": "asset_content",
                        "detail": f'{asset["url"][:180]} contains {pattern}'
                    })
                    break

        # Deduplicate evidence
        unique = []
        seen = set()
        for ev in evidence:
            key = (ev["source"], ev["detail"])
            if key not in seen:
                seen.add(key)
                unique.append(ev)

        if unique:
            sources = {e["source"] for e in unique}
            if len(sources) >= 2 or len(unique) >= 3:
                confidence = "High"
            elif len(unique) == 1:
                confidence = "Medium"
            else:
                confidence = "Medium"

            found[name] = {
                "category": sig["category"],
                "version": versions[0] if versions else None,
                "confidence": confidence,
                "evidence": unique
            }

    return found, {
        "assets_found": len(assets),
        "assets_inspected": len(asset_contents)
    }


def build(url, page, found, asset_stats):
    title = re.search(
        r"<title[^>]*>(.*?)</title>",
        page["html"], re.I | re.S
    )

    try:
        host = urlparse(page["final"]).hostname
        ip = socket.gethostbyname(host) if host else "-"
    except (socket.error, TypeError, ValueError):
        ip = "-"

    techs = {}
    for name, item in found.items():
        cat = item["category"]
        techs.setdefault(cat, []).append({
            "name": name,
            "version": item["version"],
            "confidence": item["confidence"],
            "evidence": item["evidence"]
        })

    return {
        "tool": "Jatayu",
        "version": VERSION,
        "target": url,
        "final_url": page["final"],
        "status": f'{page["status"]} {page["reason"]}'.strip(),
        "ip": ip,
        "time": round(page["time"], 2),
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:100]
                 if title else "",
        "server": page["headers"].get("server", ""),
        "powered_by": page["headers"].get("x-powered-by", ""),
        "technologies": techs,
        "asset_scan": asset_stats,
        "security_headers": {
            h: h.lower() in page["headers"] for h in SEC_HEADERS
        }
    }


def vulnerability_lookup(techs, timeout):
    """Return NVD keyword candidates, not confirmed vulnerability findings."""
    results = []
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    for category, items in techs.items():
        for item in items:
            name = item["name"]
            version = item["version"]
            if not version:
                continue

            query = f"{name} {version}"
            url = base + "?" + urlencode({
                "keywordSearch": query,
                "resultsPerPage": 5
            })

            try:
                req = Request(url, headers={"User-Agent": UA})
                with urlopen(req, timeout=timeout) as response:
                    data = json.loads(
                        response.read().decode("utf-8")
                    )

                for entry in data.get("vulnerabilities", []):
                    cve = entry.get("cve", {})
                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (d.get("value", "") for d in descriptions
                         if d.get("lang") == "en"), ""
                    )
                    results.append({
                        "technology": name,
                        "detected_version": version,
                        "cve": cve.get("id", "Unknown"),
                        "description": description[:500],
                        "status": "Candidate - verify affected versions",
                        "source": "NVD"
                    })

                time.sleep(0.7)

            except Exception as e:
                results.append({
                    "technology": name,
                    "detected_version": version,
                    "status": "Lookup failed",
                    "error": str(e)[:200]
                })

    return results


def render(r):
    def row(k, v):
        if v:
            print(f"{k:<18}{v}")

    print(f'Jatayu {r["version"]}\n')
    row("Target", r["target"])
    if r["final_url"].rstrip("/") != r["target"].rstrip("/"):
        row("Final URL", r["final_url"])
    row("Status", r["status"])
    row("IP", r["ip"])
    row("Time", f'{r["time"]}s')
    row("Title", r["title"])
    row("Server", r["server"])
    row("Powered By", r["powered_by"])

    stats = r["asset_scan"]
    print(
        f'Assets inspected: {stats["assets_inspected"]}'
        f'/{stats["assets_found"]}'
    )

    techs = r["technologies"]
    for cat in sorted(
        techs, key=lambda c: ORDER.index(c) if c in ORDER else 99
    ):
        print(f"\n{cat}")
        for t in sorted(techs[cat], key=lambda x: x["name"]):
            ver = f' {t["version"]}' if t["version"] else ""
            print(f'  {t["name"]}{ver} [{t["confidence"]}]')
            for ev in t["evidence"]:
                print(f'    [{ev["source"]}] {ev["detail"]}')

    if not techs:
        print("\nNo technologies detected")

    sec = r["security_headers"]
    print(f"\nSecurity Headers {sum(sec.values())}/{len(sec)}")
    for h, ok in sec.items():
        print(f"  {'+' if ok else '-'} {h}")

    if "vulnerabilities" in r:
        print("\nVulnerability Lookup")
        if not r["vulnerabilities"]:
            print("  No candidate CVEs returned.")
        for v in r["vulnerabilities"]:
            if "cve" in v:
                print(
                    f'  {v["technology"]} {v["detected_version"]}: '
                    f'{v["cve"]}'
                )
                print(f'    {v["status"]}')
                print(f'    {v["description"]}')
            else:
                print(
                    f'  {v["technology"]}: '
                    f'{v.get("status", "Unknown")}'
                )


def main():
    p = argparse.ArgumentParser(
        prog="jatayu",
        description="Jatayu - web technology fingerprinting"
    )
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="identify website technologies")
    s.add_argument("url")
    s.add_argument("-t", "--timeout", type=int, default=10)
    s.add_argument("-k", "--insecure", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("--vuln-check", action="store_true")
    args = p.parse_args()

    if args.cmd != "scan":
        p.print_help()
        sys.exit(2)

    url = args.url if "://" in args.url else "https://" + args.url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        sys.exit("jatayu: invalid URL")

    signatures = load_signatures()

    try:
        page = fetch(url, args.timeout, not args.insecure)
        found, stats = detect(
            page, signatures, args.timeout, not args.insecure
        )
    except (URLError, HTTPException, socket.timeout, ssl.SSLError,
            OSError, ValueError) as e:
        msg = f"jatayu: cannot reach {url} ({getattr(e, 'reason', e)})"
        if "CERTIFICATE" in str(e).upper():
            msg += "\nhint: use -k to skip TLS verification"
        sys.exit(msg)

    result = build(url, page, found, stats)

    if args.vuln_check:
        result["vulnerabilities"] = vulnerability_lookup(
            result["technologies"], args.timeout
        )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        render(result)


if __name__ == "__main__":
    main()
