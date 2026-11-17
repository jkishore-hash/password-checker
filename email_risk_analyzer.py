#!/usr/bin/env python3
"""
Email Risk Analyzer
===================
Scans email content and flags potentially unsafe messages by detecting:

  * Urgent / pressuring language
  * Suspicious or unknown links (IP hosts, URL shorteners, lookalike domains,
    mismatched link text, odd TLDs, punycode, "@" tricks)
  * Requests for sensitive data (passwords, OTPs, card numbers, SSN, etc.)
  * Sender spoofing signs (display-name/address mismatch, Reply-To mismatch)
  * Risky attachments (.exe, .scr, .js, macro-enabled Office files, ...)
  * Other social-engineering patterns (prizes, gift cards, crypto, payment changes)

Usage
-----
    python email_risk_analyzer.py --demo                 # run built-in samples
    python email_risk_analyzer.py message.eml            # analyze an .eml file
    python email_risk_analyzer.py note.txt               # analyze plain text
    cat message.eml | python email_risk_analyzer.py -    # read from stdin
    python email_risk_analyzer.py message.eml --json     # machine-readable output
    python email_risk_analyzer.py a.eml b.eml --threshold 40

Only the Python standard library is required (Python 3.8+).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from email import policy
from email.parser import BytesParser, Parser
from html.parser import HTMLParser
from typing import List, Optional, Tuple
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Score boundaries for the final verdict (0-100 scale)
MEDIUM_THRESHOLD = 25
HIGH_THRESHOLD = 55

URGENCY_PHRASES = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\basap\b", r"\bact now\b",
    r"\bright away\b", r"\bwithin \d+ ?(hours?|hrs?|minutes?|mins?)\b",
    r"\bfinal (notice|warning|reminder)\b", r"\blast (chance|warning)\b",
    r"\baccount (will be )?(suspended|locked|closed|disabled|terminated)\b",
    r"\bverify (your )?(account|identity)\b", r"\bsuspicious activity\b",
    r"\bunauthori[sz]ed (login|access|transaction)\b", r"\baction required\b",
    r"\bexpires? (today|soon|in)\b", r"\bfailure to (respond|comply)\b",
    r"\byour (account|access) (has been|will be)\b",
]

SENSITIVE_PHRASES = [
    r"\b(confirm|verify|update|enter|provide|send|reply with)\b.{0,40}\b(password|passcode|pin)\b",
    r"\bone[- ]time (password|code|pin)\b", r"\b(otp|2fa|verification) code\b",
    r"\bcredit card\b", r"\bdebit card\b", r"\bcard number\b", r"\bcvv\b",
    r"\bsocial security\b", r"\bssn\b", r"\baadhaar\b", r"\bpan (card|number)\b",
    r"\bbank account (number|details)\b", r"\brouting number\b", r"\biban\b",
    r"\bnet ?banking\b", r"\blog ?in (credentials|details)\b",
    r"\bsecurity question\b", r"\bdate of birth\b", r"\bmother'?s maiden name\b",
    r"\bseed phrase\b", r"\brecovery phrase\b", r"\bprivate key\b",
]

SOCIAL_ENGINEERING_PHRASES = [
    r"\byou('ve| have) (won|been selected)\b", r"\blottery\b", r"\bprize\b",
    r"\bclaim your (reward|gift|refund|prize)\b", r"\bgift cards?\b",
    r"\bwire transfer\b", r"\bbitcoin\b|\bcrypto(currency)?\b",
    r"\bchange (of )?(bank|payment) (details|account)\b",
    r"\bkindly (do the needful|revert)\b", r"\bdear (customer|user|client|valued)\b",
    r"\b(inheritance|beneficiary)\b", r"\bconfidential\b.{0,30}\b(do not|don't) (tell|share)\b",
    r"\brefund (is )?(pending|available)\b", r"\btax refund\b",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in",
    "s.id", "bl.ink", "v.gd",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "gq", "tk", "ml", "cf", "ga",
    "work", "support", "country", "kim", "loan", "men", "party", "review",
    "stream", "download", "racing", "win", "bid", "icu", "cyou", "rest",
}

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".ps1", ".msi", ".jar", ".lnk", ".hta", ".iso", ".img",
    ".dll", ".reg", ".apk",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlsb"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}

# Brands commonly impersonated; used to spot lookalike domains.
BRAND_DOMAINS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "docusign": "docusign.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "hdfc": "hdfcbank.com",
    "icici": "icicibank.com", "sbi": "sbi.co.in", "dhl": "dhl.com", "fedex": "fedex.com",
}

# Free webmail providers (relevant when a message claims to be from a company).
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
             "proton.me", "protonmail.com", "mail.com", "gmx.com"}

URL_REGEX = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""")
EMAIL_REGEX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
IPV4_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    category: str       # e.g. "urgency", "link", "sensitive-data"
    description: str
    score: int          # contribution to the risk score
    evidence: str = ""


@dataclass
class ParsedEmail:
    subject: str = ""
    sender_name: str = ""
    sender_addr: str = ""
    reply_to_addr: str = ""
    body_text: str = ""
    # (display_text, href) tuples extracted from HTML anchors
    html_links: List[Tuple[str, str]] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    score: int
    verdict: str
    findings: List[Finding]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "findings": [asdict(f) for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

class _AnchorExtractor(HTMLParser):
    """Collects <a href> targets with their visible text, plus plain text."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self.text_parts: List[str] = []
        self._href: Optional[str] = None
        self._anchor_text: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((" ".join(self._anchor_text).strip(), self._href))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data.strip())


def parse_email(raw: str | bytes) -> ParsedEmail:
    """Parse a raw RFC-822 message OR plain text into a ParsedEmail."""
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    else:
        text = raw
        msg = Parser(policy=policy.default).parsestr(raw)

    parsed = ParsedEmail()

    # If it has no recognisable headers, treat the whole thing as a plain body.
    has_headers = any(h in msg for h in ("From", "Subject", "To"))
    if not has_headers:
        parsed.body_text = text
        _extract_html_links(parsed, text)
        return parsed

    parsed.subject = str(msg.get("Subject", "") or "")
    from_hdr = str(msg.get("From", "") or "")
    name, addr = _split_address(from_hdr)
    parsed.sender_name, parsed.sender_addr = name, addr
    _, parsed.reply_to_addr = _split_address(str(msg.get("Reply-To", "") or ""))

    html_chunks: List[str] = []
    text_chunks: List[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            parsed.attachments.append(filename)
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            html_chunks.append(content)
        elif ctype == "text/plain":
            text_chunks.append(content)

    for html in html_chunks:
        extractor = _AnchorExtractor()
        try:
            extractor.feed(html)
        except Exception:
            pass
        parsed.html_links.extend(extractor.links)
        text_chunks.append(" ".join(extractor.text_parts))

    parsed.body_text = "\n".join(text_chunks).strip()
    return parsed


def _extract_html_links(parsed: ParsedEmail, text: str) -> None:
    if "<a " in text.lower():
        ex = _AnchorExtractor()
        try:
            ex.feed(text)
        except Exception:
            return
        parsed.html_links.extend(ex.links)
        parsed.body_text = " ".join(ex.text_parts)


def _split_address(header: str) -> Tuple[str, str]:
    match = EMAIL_REGEX.search(header)
    addr = match.group(0).lower() if match else ""
    name = header.replace(match.group(0), "") if match else header
    name = re.sub(r"[<>\"']", "", name).strip()
    return name, addr


def _domain_of(url: str) -> str:
    if not re.match(r"(?i)^https?://", url):
        url = "http://" + url
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""
    return host.lower().rstrip(".")


def _registered_domain(host: str) -> str:
    """Rough registrable domain (handles a few common 2-level TLDs)."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {"co.uk", "co.in", "com.au", "co.jp", "com.br", "org.uk", "ac.in", "gov.in"}
    last_two = ".".join(parts[-2:])
    if last_two in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #

def _match_phrases(patterns: List[str], text: str) -> List[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            hits.append(m.group(0).strip())
    return hits


def detect_urgency(text: str) -> List[Finding]:
    hits = _match_phrases(URGENCY_PHRASES, text)
    if not hits:
        return []
    score = min(8 + 5 * (len(hits) - 1), 25)
    return [Finding("urgency", "Urgent or pressuring language detected", score,
                    "; ".join(dict.fromkeys(h.lower() for h in hits[:6])))]


def detect_sensitive_requests(text: str) -> List[Finding]:
    hits = _match_phrases(SENSITIVE_PHRASES, text)
    if not hits:
        return []
    score = min(15 + 6 * (len(hits) - 1), 35)
    return [Finding("sensitive-data", "Message asks for or mentions sensitive information", score,
                    "; ".join(dict.fromkeys(h.lower()[:60] for h in hits[:6])))]


def detect_social_engineering(text: str) -> List[Finding]:
    hits = _match_phrases(SOCIAL_ENGINEERING_PHRASES, text)
    if not hits:
        return []
    score = min(6 + 4 * (len(hits) - 1), 18)
    return [Finding("social-engineering", "Common scam / social-engineering wording", score,
                    "; ".join(dict.fromkeys(h.lower()[:60] for h in hits[:6])))]


def detect_link_issues(parsed: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []
    seen: set = set()

    urls = [m.group(1) for m in URL_REGEX.finditer(parsed.body_text)]
    urls += [href for _, href in parsed.html_links if href.lower().startswith(("http", "www"))]

    for url in urls:
        host = _domain_of(url)
        if not host or host in seen:
            continue
        seen.add(host)
        reg = _registered_domain(host)
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        if IPV4_REGEX.match(host):
            findings.append(Finding("link", "Link points to a raw IP address", 18, url[:100]))
        if host in URL_SHORTENERS or reg in URL_SHORTENERS:
            findings.append(Finding("link", "URL shortener hides the real destination", 10, url[:100]))
        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding("link", f"Link uses a high-abuse TLD (.{tld})", 10, url[:100]))
        if "xn--" in host:
            findings.append(Finding("link", "Punycode domain (possible lookalike characters)", 15, host))
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            findings.append(Finding("link", "URL contains '@' (credential-style obfuscation)", 15, url[:100]))
        if host.count(".") >= 4:
            findings.append(Finding("link", "Unusually deep subdomain chain", 8, host))
        if url.lower().startswith("http://"):
            findings.append(Finding("link", "Link is not encrypted (HTTP, not HTTPS)", 4, url[:100]))

        # Brand impersonation: brand name inside a domain that isn't the real one
        for brand, real in BRAND_DOMAINS.items():
            if brand in host and reg != real and not host.endswith("." + real):
                findings.append(Finding(
                    "link", f"Domain imitates '{brand}' but is not {real}", 22, host))
                break

        # Digit-for-letter swaps (paypa1, micr0soft...)
        deobf = host.translate(str.maketrans("01358", "oleba"))
        for brand, real in BRAND_DOMAINS.items():
            if deobf != host and brand in deobf and reg != real:
                findings.append(Finding(
                    "link", f"Look-alike character substitution mimicking '{brand}'", 22, host))
                break

    # Visible text shows one domain, actual href goes elsewhere
    for text, href in parsed.html_links:
        if not href.lower().startswith(("http", "www")):
            continue
        shown = URL_REGEX.search(text or "")
        if shown:
            shown_dom = _registered_domain(_domain_of(shown.group(1)))
            real_dom = _registered_domain(_domain_of(href))
            if shown_dom and real_dom and shown_dom != real_dom:
                findings.append(Finding(
                    "link", "Link text shows a different site than the real destination", 25,
                    f"shows {shown_dom} -> goes to {real_dom}"))

    if len(seen) >= 6:
        findings.append(Finding("link", "Unusually high number of distinct link domains", 5,
                                f"{len(seen)} domains"))
    return findings


def detect_sender_issues(parsed: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []
    addr, name = parsed.sender_addr, parsed.sender_name
    if not addr:
        return findings
    domain = addr.split("@", 1)[-1]

    # Reply-To differs from From
    if parsed.reply_to_addr:
        rt_domain = parsed.reply_to_addr.split("@", 1)[-1]
        if rt_domain != domain:
            findings.append(Finding("sender", "Reply-To domain differs from sender domain", 15,
                                    f"{domain} vs {rt_domain}"))

    # Display name embeds a different email address
    embedded = EMAIL_REGEX.search(name)
    if embedded and embedded.group(0).lower() != addr:
        findings.append(Finding("sender", "Display name contains a different email address", 20,
                                name[:80]))

    lowered = name.lower()
    for brand, real in BRAND_DOMAINS.items():
        if brand in lowered and _registered_domain(domain) != real:
            kind = "free webmail account" if domain in FREE_MAIL else f"domain {domain}"
            findings.append(Finding("sender", f"Sender claims to be '{brand}' but uses {kind}", 22,
                                    f"{name} <{addr}>"))
            break

    # Lookalike sender domain
    deobf = domain.translate(str.maketrans("01358", "oleba"))
    for brand, real in BRAND_DOMAINS.items():
        if brand in deobf and _registered_domain(domain) != real:
            findings.append(Finding("sender", f"Sender domain looks like '{brand}' impersonation", 22, domain))
            break

    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(Finding("sender", "Sender uses a high-abuse TLD", 8, domain))
    return findings


def detect_attachment_issues(parsed: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []
    for fname in parsed.attachments:
        low = fname.lower()
        parts = low.split(".")
        ext = "." + parts[-1] if len(parts) > 1 else ""
        if len(parts) > 2 and ("." + parts[-2]) in {".pdf", ".doc", ".docx", ".xls", ".jpg", ".png", ".txt"} \
                and ext in RISKY_EXTENSIONS:
            findings.append(Finding("attachment", "Double extension disguising an executable", 30, fname))
        elif ext in RISKY_EXTENSIONS:
            findings.append(Finding("attachment", "Executable / script attachment", 28, fname))
        elif ext in MACRO_EXTENSIONS:
            findings.append(Finding("attachment", "Macro-enabled Office document", 20, fname))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(Finding("attachment", "Archive attachment (can hide malware)", 8, fname))
    return findings


def detect_formatting_issues(parsed: ParsedEmail) -> List[Finding]:
    findings: List[Finding] = []
    subject = parsed.subject
    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        findings.append(Finding("formatting", "Subject line is mostly ALL CAPS", 5, subject[:80]))
    if (subject + parsed.body_text).count("!") >= 4:
        findings.append(Finding("formatting", "Excessive exclamation marks", 4))
    if re.search(r"[\u0400-\u04FF\u0370-\u03FF]", parsed.sender_name + subject) and \
            re.search(r"[A-Za-z]", parsed.sender_name + subject):
        findings.append(Finding("formatting", "Mixed Latin and Cyrillic/Greek characters (homoglyph risk)", 12))
    return findings


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def analyze(parsed: ParsedEmail, medium: int = MEDIUM_THRESHOLD,
            high: int = HIGH_THRESHOLD) -> AnalysisResult:
    full_text = f"{parsed.subject}\n{parsed.body_text}"
    findings: List[Finding] = []
    findings += detect_urgency(full_text)
    findings += detect_sensitive_requests(full_text)
    findings += detect_social_engineering(full_text)
    findings += detect_link_issues(parsed)
    findings += detect_sender_issues(parsed)
    findings += detect_attachment_issues(parsed)
    findings += detect_formatting_issues(parsed)

    # Combination bonus: urgency + sensitive request + link is the classic phish.
    cats = {f.category for f in findings}
    if {"urgency", "sensitive-data", "link"} <= cats:
        findings.append(Finding("combo", "Urgency + sensitive-data request + suspicious link (classic phishing pattern)", 15))
    elif {"urgency", "link"} <= cats or {"sensitive-data", "link"} <= cats:
        findings.append(Finding("combo", "Pressure or data request combined with suspicious link", 8))

    score = min(sum(f.score for f in findings), 100)
    if score >= high:
        verdict = "HIGH RISK"
    elif score >= medium:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"
    findings.sort(key=lambda f: f.score, reverse=True)
    return AnalysisResult(score, verdict, findings)


def analyze_text(raw: str | bytes, **kwargs) -> AnalysisResult:
    """Convenience wrapper: parse + analyze in one call."""
    return analyze(parse_email(raw), **kwargs)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

_COLORS = {"HIGH RISK": "\033[91m", "MEDIUM RISK": "\033[93m", "LOW RISK": "\033[92m"}
_RESET = "\033[0m"


def format_report(label: str, parsed: ParsedEmail, result: AnalysisResult, color: bool = True) -> str:
    c = _COLORS.get(result.verdict, "") if color else ""
    r = _RESET if color else ""
    bar_len = 30
    filled = round(result.score / 100 * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)

    lines = [
        "=" * 64,
        f"Email: {label}",
    ]
    if parsed.subject:
        lines.append(f"Subject: {parsed.subject}")
    if parsed.sender_addr:
        lines.append(f"From:    {parsed.sender_name} <{parsed.sender_addr}>".replace("  ", " "))
    lines += [
        "-" * 64,
        f"Verdict: {c}{result.verdict}{r}   Score: {result.score}/100",
        f"[{bar}]",
        "",
    ]
    if result.findings:
        lines.append("Flags raised:")
        for f in result.findings:
            lines.append(f"  [{f.category.upper():<18}] +{f.score:<3} {f.description}")
            if f.evidence:
                lines.append(f"      -> {f.evidence}")
    else:
        lines.append("No suspicious indicators found.")

    if result.verdict != "LOW RISK":
        lines += [
            "",
            "Recommendation: Do NOT click links, open attachments, or reply with personal",
            "information. Verify the sender through a separate, trusted channel.",
        ]
    lines.append("=" * 64)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Demo samples
# --------------------------------------------------------------------------- #

DEMO_EMAILS = {
    "Phishing example": """From: "PayPal Security" <support@paypa1-secure.top>
Reply-To: helpdesk@collector-mail.xyz
Subject: URGENT: Your account will be suspended within 24 hours!!!

Dear Customer,

We detected suspicious activity on your account. Action required immediately.
Verify your account and confirm your password, credit card number and CVV here:

http://185.44.23.9/paypal/login

Or click <a href="http://bit.ly/3xYzAbC">https://www.paypal.com/verify</a>

Failure to respond will result in permanent closure.
""",
    "Malicious attachment example": """From: Accounts <billing@random-vendor.work>
Subject: Invoice attached
Content-Type: multipart/mixed; boundary="XX"

--XX
Content-Type: text/plain

Please find the invoice attached. Kindly do the needful.
--XX
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice_8841.pdf.exe"

AAAA
--XX--
""",
    "Legitimate example": """From: Priya Sharma <priya@acme-corp.com>
To: team@acme-corp.com
Subject: Weekly sync notes

Hi team,

Here are the notes from today's sync. Slides are at https://docs.acme-corp.com/weekly.
Let me know if I missed anything. Thanks!

Priya
""",
}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _read_source(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Scan emails for phishing / unsafe-content indicators.")
    ap.add_argument("files", nargs="*", help="Email files (.eml or text). Use '-' for stdin.")
    ap.add_argument("--demo", action="store_true", help="Analyze built-in sample emails.")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of a text report.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    ap.add_argument("--threshold", type=int, default=HIGH_THRESHOLD,
                    help=f"Score at/above which a message is HIGH RISK (default {HIGH_THRESHOLD}).")
    args = ap.parse_args(argv)

    if not args.files and not args.demo:
        ap.print_help()
        return 2

    medium = min(MEDIUM_THRESHOLD, args.threshold)
    jobs: List[Tuple[str, bytes | str]] = []
    if args.demo:
        jobs += list(DEMO_EMAILS.items())
    for path in args.files:
        try:
            jobs.append((path, _read_source(path)))
        except OSError as exc:
            print(f"Error reading {path}: {exc}", file=sys.stderr)
            return 1

    json_out = []
    worst = "LOW RISK"
    order = ["LOW RISK", "MEDIUM RISK", "HIGH RISK"]
    use_color = sys.stdout.isatty() and not args.no_color

    for label, raw in jobs:
        parsed = parse_email(raw)
        result = analyze(parsed, medium=medium, high=args.threshold)
        if order.index(result.verdict) > order.index(worst):
            worst = result.verdict
        if args.json:
            json_out.append({"source": label, "subject": parsed.subject,
                             "sender": parsed.sender_addr, **result.to_dict()})
        else:
            print(format_report(label, parsed, result, color=use_color))
            print()

    if args.json:
        print(json.dumps(json_out, indent=2))

    # Exit code is handy for scripting / mail-filter integration
    return {"LOW RISK": 0, "MEDIUM RISK": 1, "HIGH RISK": 2}[worst]


if __name__ == "__main__":
    sys.exit(main())
