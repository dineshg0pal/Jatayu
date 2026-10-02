<div align="center">

<img src="assets/logo.jpeg" width="140" alt="Jatayu logo"/>

# Jatayu

**A simple, single-file web technology fingerprinting tool.**

![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-brightgreen)

</div>

---

## What is Jatayu?

Jatayu looks at a website and tells you what it's built with — the web
server, the CMS, the JavaScript frameworks, the analytics scripts, the CDN,
and more. It works the same way tools like **Wappalyzer** and **WhatWeb**
do: it reads HTTP headers, cookies, HTML, and linked scripts, and matches
them against a list of known signatures.

It's a single Python file with no dependencies outside the standard
library, and a plain-text signature list you can edit yourself.

## What makes it different

- **One file, zero installs.** No `pip install`, no virtual environment.
  Just `python3 jatayu.py`.
- **Editable signatures.** `technologies.txt` is plain JSON. Add or change
  a detection rule without touching the code.
- **Clean, readable output.** No clutter — just the target, what was
  found, and the evidence behind each match.
- **Goes past the homepage.** It also pulls in linked JavaScript and CSS
  files to catch what the raw HTML alone would miss.
- **Optional extras**, off by default:
  - `--vuln-check` — look up candidate CVEs for detected versions
  - `--find-origin` — passive recon (crt.sh + DNS) to help spot an origin
    server hiding behind a CDN

## Installation

Jatayu needs only Python 3.8 or newer. There is nothing to install.

```bash
git clone https://github.com/dineshg0pal/Jatayu.git
cd Jatayu
```

Make sure `jatayu.py` and `technologies.txt` are in the same folder.

## Usage

Check the tool version:

```bash
python3 jatayu.py --version
```

Scan a website:

```bash
python3 jatayu.py scan https://example.com
```

### Example output

```
Jatayu 1.2

Target                example.com
Status                200 OK
Server                nginx

Web Server
  nginx 1.18.0 [High]
    [header] server: nginx/1.18.0

CMS
  WordPress [High]
    [meta] generator: WordPress 6.4
```

### Common options

| Flag              | What it does                                      |
|-------------------|----------------------------------------------------|
| `-t`, `--timeout` | Request timeout in seconds (default: 10)           |
| `-k`, `--insecure`| Skip TLS certificate verification                  |
| `--json`          | Print results as JSON instead of plain text         |
| `--vuln-check`    | Look up candidate CVEs for detected versions         |
| `--find-origin`   | Passive origin-IP recon (crt.sh + DNS)               |
| `--output FILE` | Save a plain-text report to FILE while preserving terminal output |

```bash
python3 jatayu.py scan https://example.com --json
python3 jatayu.py scan https://example.com --vuln-check
python3 jatayu.py scan https://example.com --find-origin
```

Save a plain-text report while also printing it to the terminal:

```bash
python3 jatayu.py scan https://example.com --output result.txt
```

The file is written using UTF-8 encoding. An existing file is overwritten.
When combined with `--json`, terminal output remains JSON and the saved
report is plain text.


## Adding your own signatures

Open `technologies.txt` and add an entry:

```json
{
  "name": "My Framework",
  "category": "Web Framework",
  "headers": { "x-powered-by": "MyFramework" },
  "body": ["my-framework.js"]
}
```

Supported match types: `headers`, `meta`, `cookies`, `body`, `assets`,
`asset_content`.

## Legal

Jatayu is for use on systems you own or have explicit permission to test.
`--find-origin` only reads public DNS and Certificate Transparency records
— it never contacts the target directly — but any IP it surfaces should
still only be investigated further with proper authorization.

## Credits

Inspired by [Wappalyzer](https://www.wappalyzer.com/) and
[wig](https://github.com/jekyc/wig).

## License

MIT
