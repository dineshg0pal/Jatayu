#!/usr/bin/env python3
"""Jatayu - web technology fingerprinting.
Usage: python3 jatayu scan https://example.com"""
import argparse, json, re, socket, ssl, sys, time, zlib
from http.client import HTTPException, IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

VERSION = "1.0"
UA = "Mozilla/5.0 (compatible; Jatayu/1.0)"
MAX_BYTES = 2_000_000


def S(name, cat, **rules):
    # h: {header: regex}  m: {meta: regex}  c: cookie-name regex
    # s: script/stylesheet URL regex  b: page-body regex
    # First capture group in a regex = version
    return (name, cat, rules)


SIGS = [
    # Web servers
    S("nginx", "Web Server", h={"server": r"nginx(?:/([\d.]+))?"}),
    S("Apache", "Web Server", h={"server": r"Apache(?!-Coyote)(?:/([\d.]+))?"}),
    S("Apache Tomcat", "Web Server", h={"server": r"Apache-Coyote|Tomcat"}),
    S("Microsoft IIS", "Web Server", h={"server": r"Microsoft-IIS(?:/([\d.]+))?"}),
    S("LiteSpeed", "Web Server", h={"server": r"LiteSpeed"}),
    S("OpenResty", "Web Server", h={"server": r"openresty(?:/([\d.]+))?"}),
    S("Caddy", "Web Server", h={"server": r"Caddy"}),
    S("Gunicorn", "Web Server", h={"server": r"gunicorn(?:/([\d.]+))?"}),
    # CDN / WAF
    S("Cloudflare", "CDN / WAF", h={"server": r"cloudflare", "cf-ray": ""}),
    S("Amazon CloudFront", "CDN / WAF", h={"via": r"CloudFront", "x-amz-cf-id": ""}),
    S("Akamai", "CDN / WAF", h={"server": r"Akamai\w*", "x-akamai-request-id": ""}),
    S("Fastly", "CDN / WAF", h={"x-fastly-request-id": "", "fastly-debug-digest": ""}),
    S("Sucuri", "CDN / WAF", h={"x-sucuri-id": ""}),
    S("Imperva Incapsula", "CDN / WAF", c=r"^(?:incap_ses|visid_incap)"),
    S("AWS Load Balancer", "CDN / WAF", c=r"^AWSALB"),
    # Caching / hosting
    S("Varnish", "Caching", h={"via": r"varnish", "x-varnish": ""}),
    S("Vercel", "Hosting", h={"server": r"Vercel", "x-vercel-id": ""}),
    S("Netlify", "Hosting", h={"server": r"Netlify", "x-nf-request-id": ""}),
    S("GitHub Pages", "Hosting", h={"server": r"GitHub\.com"}),
    # Languages
    S("PHP", "Programming Language", h={"x-powered-by": r"PHP/?([\d.]+)?"}, c=r"^PHPSESSID$"),
    S("ASP.NET", "Programming Language",
      h={"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"([\d.]+)"}, c=r"^ASP\.NET_SessionId$"),
    S("Java", "Programming Language", c=r"^JSESSIONID$"),
    # Frameworks
    S("Express", "Web Framework", h={"x-powered-by": r"Express"}),
    S("Django", "Web Framework", c=r"^csrftoken$", b=r"csrfmiddlewaretoken"),
    S("Laravel", "Web Framework", c=r"^laravel_session$"),
    S("Ruby on Rails", "Web Framework", m={"csrf-param": r"authenticity_token"}),
    S("Next.js", "Web Framework", h={"x-powered-by": r"Next\.js"}, b=r"/_next/static/"),
    S("Nuxt.js", "Web Framework", b=r"/_nuxt/"),
    # CMS / e-commerce
    S("WordPress", "CMS", m={"generator": r"WordPress\s*([\d.]+)?"}, b=r"/wp-(?:content|includes)/"),
    S("Drupal", "CMS", m={"generator": r"Drupal\s*([\d.]+)?"}, h={"x-generator": r"Drupal\s*([\d.]+)?"},
      b=r"/sites/(?:default|all)/(?:files|modules|themes)/"),
    S("Joomla", "CMS", m={"generator": r"Joomla!?\s*([\d.]+)?"}, b=r"/media/jui/|/components/com_"),
    S("Ghost", "CMS", m={"generator": r"Ghost\s*([\d.]+)?"}),
    S("TYPO3", "CMS", m={"generator": r"TYPO3"}, b=r"/typo3(?:conf|temp)/"),
    S("Wix", "CMS", m={"generator": r"Wix\.com"}, b=r"wixstatic\.com"),
    S("Squarespace", "CMS", b=r"static1?\.squarespace\.com"),
    S("Webflow", "CMS", m={"generator": r"Webflow"}, b=r"data-wf-(?:page|site)"),
    S("Shopify", "E-commerce", b=r"cdn\.shopify\.com"),
    S("WooCommerce", "E-commerce", m={"generator": r"WooCommerce\s*([\d.]+)?"}, b=r"/plugins/woocommerce/"),
    S("Magento", "E-commerce", b=r"/static/frontend/|Mage\.Cookies|/skin/frontend/"),
    S("PrestaShop", "E-commerce", m={"generator": r"PrestaShop"}),
    # JS frameworks / libraries
    S("React", "JavaScript Framework", b=r"data-reactroot|data-reactid",
      s=r"(?<![a-z])react(?:-dom)?(?:[-@/.](\d+\.\d+\.\d+))?(?:\.production)?(?:\.min)?\.js"),
    S("Vue.js", "JavaScript Framework", b=r"data-v-[0-9a-f]{8}",
      s=r"(?<![a-z])vue(?:\.runtime)?(?:[-@/.](\d+\.\d+\.\d+))?(?:\.global)?(?:\.prod)?(?:\.min)?\.js"),
    S("Angular", "JavaScript Framework", b=r'ng-version="([\d.]+)"', s=r"angular(?:\.min)?\.js"),
    S("Alpine.js", "JavaScript Framework", s=r"alpine(?:js)?"),
    S("htmx", "JavaScript Framework", s=r"htmx"),
    S("jQuery", "JavaScript Library", s=r"jquery(?![-.]?ui)(?:[-./](\d+\.\d+(?:\.\d+)?))?"),
    S("Lodash", "JavaScript Library", s=r"lodash(?:\.min)?\.js"),
    S("Moment.js", "JavaScript Library", s=r"moment(?:-with-locales)?(?:\.min)?\.js"),
    S("Bootstrap", "UI Framework",
      s=r"bootstrap(?:[-@/.](\d+\.\d+(?:\.\d+)?))?(?:\.bundle)?(?:\.min)?\.(?:js|css)"),
    S("Tailwind CSS", "UI Framework", s=r"tailwind(?:css)?(?:[-@/.](\d+\.\d+\.\d+))?"),
    S("Font Awesome", "Fonts & Icons", s=r"font-?awesome(?:[/@-](\d+\.\d+(?:\.\d+)?))?"),
    S("Google Fonts", "Fonts & Icons", s=r"fonts\.googleapis\.com"),
    # Analytics
    S("Google Analytics", "Analytics", s=r"google-analytics\.com|googletagmanager\.com/gtag/js"),
    S("Google Tag Manager", "Analytics", s=r"googletagmanager\.com/gtm\.js", b=r"googletagmanager\.com/ns\.html"),
    S("Facebook Pixel", "Analytics", s=r"connect\.facebook\.net/.+/fbevents\.js", b=r"fbq\('init'"),
    S("Hotjar", "Analytics", s=r"static\.hotjar\.com"),
    S("Matomo", "Analytics", s=r"matomo\.js|piwik\.js", b=r"_paq\.push"),
    S("Microsoft Clarity", "Analytics", s=r"clarity\.ms"),
    S("Plausible", "Analytics", s=r"plausible\.io/js"),
    # Security / payments
    S("reCAPTCHA", "Security", b=r"google\.com/recaptcha|grecaptcha"),
    S("hCaptcha", "Security", s=r"hcaptcha\.com"),
    S("Cloudflare Turnstile", "Security", s=r"challenges\.cloudflare\.com/turnstile"),
    S("Stripe", "Payment", s=r"js\.stripe\.com"),
    S("PayPal", "Payment", s=r"paypal\.com/sdk|paypalobjects\.com"),
]

ORDER = ["Web Server", "CDN / WAF", "Caching", "Hosting", "Programming Language",
         "Web Framework", "CMS", "E-commerce", "JavaScript Framework", "JavaScript Library",
         "UI Framework", "Fonts & Icons", "Analytics", "Security", "Payment"]

SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
               "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]


def read_body(resp):
    """Read up to MAX_BYTES; keep partial data if the server cuts the connection."""
    chunks, size = [], 0
    try:
        while size < MAX_BYTES:
            chunk = resp.read(min(65536, MAX_BYTES - size))
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


def fetch(url, timeout, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.8",
                                "Accept-Encoding": "gzip, identity"})
    start = time.time()
    try:
        resp = urlopen(req, timeout=timeout, context=ctx)
    except HTTPError as e:  # 403/404/500 pages still carry fingerprints
        resp = e
    body = read_body(resp)
    elapsed = time.time() - start
    if resp.headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            body = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body)
        except zlib.error:
            pass
    headers = {}
    for k, v in resp.headers.items():
        k = k.lower()
        headers[k] = headers[k] + ", " + v if k in headers else v
    cookies = [c.split("=", 1)[0].strip() for c in (resp.headers.get_all("Set-Cookie") or [])]
    try:
        html = body.decode(resp.headers.get_content_charset() or "utf-8", "replace")
    except LookupError:
        html = body.decode("utf-8", "replace")
    return {
        "final": resp.geturl(),
        "status": getattr(resp, "status", None) or getattr(resp, "code", 0),
        "reason": getattr(resp, "reason", "") or "",
        "headers": headers, "cookies": cookies, "html": html, "time": elapsed,
    }


def match(pattern, text):
    m = re.search(pattern, text, re.I)
    if not m:
        return False, None
    return True, (m.group(m.lastindex) if m.lastindex else None)


def detect(page):
    html, headers = page["html"], page["headers"]
    metas = {}
    for tag in re.findall(r"<meta\s[^>]*>", html, re.I):
        n = re.search(r'(?:name|property)\s*=\s*["\']([^"\']+)', tag, re.I)
        c = re.search(r'content\s*=\s*["\']([^"\']*)', tag, re.I)
        if n and c:
            metas[n.group(1).lower()] = c.group(1)
    assets = re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)', html, re.I)
    assets += re.findall(r'<link[^>]+href\s*=\s*["\']([^"\']+)', html, re.I)

    found = {}
    for name, cat, r in SIGS:
        hits = []
        hits += [match(p, headers[k]) for k, p in r.get("h", {}).items() if k in headers]
        hits += [match(p, metas[k]) for k, p in r.get("m", {}).items() if k in metas]
        if "c" in r:
            hits += [match(r["c"], c) for c in page["cookies"]]
        if "s" in r:
            hits += [match(r["s"], a) for a in assets]
        if "b" in r:
            hits.append(match(r["b"], html))
        for ok, ver in hits:
            if ok and (name not in found or (ver and not found[name][1])):
                found[name] = (cat, ver)
    return found


def build(url, page, found):
    title = re.search(r"<title[^>]*>(.*?)</title>", page["html"], re.I | re.S)
    try:
        ip = socket.gethostbyname(urlparse(page["final"]).hostname)
    except (socket.error, TypeError):
        ip = "-"
    techs = {}
    for name, (cat, ver) in found.items():
        techs.setdefault(cat, []).append({"name": name, "version": ver})
    return {
        "target": url, "final_url": page["final"], "status": f'{page["status"]} {page["reason"]}'.strip(),
        "ip": ip, "time": round(page["time"], 2),
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:70] if title else "",
        "server": page["headers"].get("server", ""), "powered_by": page["headers"].get("x-powered-by", ""),
        "technologies": techs,
        "security_headers": {h: h.lower() in page["headers"] for h in SEC_HEADERS},
    }


def render(r):
    def row(k, v):
        if v:
            print(f"{k:<10}{v}")

    print(f"Jatayu {VERSION}\n")
    row("Target", r["target"])
    if r["final_url"].rstrip("/") != r["target"].rstrip("/"):
        row("Final", r["final_url"])
    row("Status", r["status"])
    row("IP", r["ip"])
    row("Time", f'{r["time"]}s')
    row("Title", r["title"])
    row("Server", r["server"])
    row("Powered", r["powered_by"])
    techs = r["technologies"]
    for cat in sorted(techs, key=lambda c: ORDER.index(c) if c in ORDER else 99):
        print(f"\n{cat}")
        for t in sorted(techs[cat], key=lambda t: t["name"]):
            print(f'  {t["name"]}' + (f' {t["version"]}' if t["version"] else ""))
    if not techs:
        print("\nNo technologies detected")
    sec = r["security_headers"]
    print(f"\nSecurity Headers  {sum(sec.values())}/{len(sec)}")
    for h, ok in sec.items():
        print(f"  {'+' if ok else '-'} {h}")


def main():
    p = argparse.ArgumentParser(prog="jatayu", description="Jatayu - web technology fingerprinting")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="identify technologies used by a website")
    s.add_argument("url")
    s.add_argument("-t", "--timeout", type=int, default=10, help="timeout in seconds (default 10)")
    s.add_argument("-k", "--insecure", action="store_true", help="skip TLS certificate verification")
    s.add_argument("--json", action="store_true", help="output JSON")
    args = p.parse_args()
    if args.cmd != "scan":
        p.print_help()
        sys.exit(2)

    url = args.url if "://" in args.url else "https://" + args.url
    if not urlparse(url).netloc:
        sys.exit("jatayu: invalid URL")
    try:
        page = fetch(url, args.timeout, not args.insecure)
    except (URLError, HTTPException, socket.timeout, ssl.SSLError, OSError, ValueError) as e:
        msg = f"jatayu: cannot reach {url} ({getattr(e, 'reason', e)})"
        if "CERTIFICATE" in str(e).upper():
            msg += "\nhint: use -k to skip certificate verification"
        sys.exit(msg)

    result = build(url, page, detect(page))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        render(result)


if __name__ == "__main__":
    main()
