"""
Praedix Cold Outreach Email Enricher
Geoptimaliseerde kloon van de Praedix Website Enricher, specifiek voor cold outreach.
Focus: email + telefoon scrapen van e-commerce en recruitment bedrijfswebsites.
Verwijderd: bedrijfsgrootte scraping, team size detection, groei-indicatie.
"""
import asyncio
import re
import html as html_lib
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Iterable
from urllib.parse import urljoin, urlparse

from apify import Actor
from playwright.async_api import async_playwright, Page, Browser, BrowserContext, Route, Request

# ─── Contact pagina paden (geoptimaliseerd: alleen de meest voorkomende) ───
CONTACT_PATHS = [
    "/contact",
    "/contact-us",
    "/contacteer-ons",
    "/neem-contact-op",
    "/over-ons/contact",
    "/about/contact",
    "/nl/contact",
    "/en/contact",
    "/get-in-touch",
    "/contactgegevens",
]

FALLBACK_PATHS = [
    "/over-ons",
    "/about",
    "/about-us",
    "/info",
    "/footer",
    "/impressum",
]

# ─── Email prioritering ───
PRIORITY_PREFIXES = (
    "contact@", "info@", "sales@", "hello@", "mail@",
    "business@", "enquiries@", "support@",
    "office@", "admin@", "general@", "service@",
    "secretariaat@", "receptie@", "kantoor@",
)

EXCLUDED_PREFIXES = (
    "noreply@", "no-reply@", "donotreply@",
    "privacy@", "legal@", "dpo@",
    "abuse@", "spam@", "mailer-daemon@",
)

BAD_EMAIL_DOMAINS = {
    "ic.cloudflareinsights.com", "cloudflareinsights.com",
    "nextchapter-ecommerce.com", "example.com", "example.org", "example.net",
    "placeholder.com", "test.com", "domain.com", "yourdomain.com",
    "wixpress.com", "sentry.io", "w3.org", "schema.org",
}

BAD_DOMAIN_FRAGMENTS = (
    "cloudflareinsights", "nextchapter", "doubleclick", "googletagmanager",
    "google-analytics", "sentry", "segment", "intercom", "hotjar",
    "clarity.ms", "placeholder", "flowbite", "tailwindcss", "example",
    "wixpress", "wordpress",
)

FREE_MAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.nl", "proton.me", "protonmail.com",
    "icloud.com", "me.com", "mac.com",
}

BAD_EMAIL_TLDS = {
    "png", "jpg", "jpeg", "webp", "gif", "svg", "ico",
    "pdf", "zip", "rar", "7z", "css", "js", "map", "json", "xml", "txt",
    "woff", "woff2", "ttf", "eot", "mp3", "mp4", "webm", "mov",
}

BAD_EMAIL_VALUES = {
    "name@flowbite.com", "hello@flowbite.com", "info@flowbite.com",
    "support@flowbite.com", "email@example.com", "info@example.com",
    "contact@example.com", "user@example.com",
}

# ─── Regex patronen ───
EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b'
)

AT_OBFUSCATION_RE = re.compile(
    r"([a-zA-Z0-9._%+-]{2,})\s*(?:\(|\[)?\s*(?:at|@|&#64;|&commat;|&#x40;|AT)\s*(?:\)|\])?\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)

CF_DATA_RE = re.compile(r'data-cfemail="([0-9a-fA-F]+)"')
CF_HREF_RE = re.compile(r"/cdn-cgi/l/email-protection#([0-9a-fA-F]+)")

PHONE_LINK_RE = re.compile(r'(?:tel|phone|telephone):\s*([+\d\s\-\(\)]+)', re.IGNORECASE)
PHONE_RE = re.compile(
    r'(?:\+\d{1,3}[\s.-]?)?(?:\(0\)\s?)?(?:\d{2,4}[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}',
    re.IGNORECASE
)

MALWARE_PATTERNS = [
    "deceptive site", "phishing", "malware", "harmful",
    "this site may harm", "dangerous site", "google safe browsing",
]

MAINTENANCE_PATTERNS = [
    "maintenance", "under maintenance", "in onderhoud",
    "tijdelijk niet bereikbaar", "onder constructie", "under construction",
    "coming soon", "binnenkort beschikbaar", "website wordt vernieuwd",
]

UNCONNECTED_DOMAIN_PATTERNS = [
    "domain nog niet is gekoppeld", "not connected to a website",
    "is this your domain", "domain is parked", "parked domain",
    "this domain is for sale", "domein geparkeerd",
]

SITE_UNAVAILABLE_PATTERNS = [
    "site can't be reached", "refused to connect", "took too long to respond",
    "unable to connect", "dns_probe_finished_nxdomain", "err_name_not_resolved",
    "err_connection_refused", "err_connection_timed_out",
]


@dataclass
class Lead:
    lead_id: str
    website: str
    name: Optional[str] = None
    phone: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None


@dataclass
class PageFlags:
    isMalware: bool = False
    isMaintenance: bool = False
    isUnconnected: bool = False
    isUnavailable: bool = False


def clamp_int(val: Any, min_val: int, max_val: int, default: int) -> int:
    if not isinstance(val, (int, float)):
        return default
    return max(min_val, min(max_val, int(val)))


def decode_cf_email(encoded_hex: str) -> str:
    try:
        key = int(encoded_hex[:2], 16)
        return "".join(chr(int(encoded_hex[i:i+2], 16) ^ key) for i in range(2, len(encoded_hex), 2))
    except Exception:
        return ""


def collect_emails_from_html(html: str) -> Iterable[str]:
    for match in CF_DATA_RE.finditer(html):
        email = decode_cf_email(match.group(1))
        if email:
            yield email
    for match in CF_HREF_RE.finditer(html):
        email = decode_cf_email(match.group(1))
        if email:
            yield email
    for match in EMAIL_RE.finditer(html):
        yield match.group(0)


def collect_emails_from_text(text: str) -> Iterable[str]:
    for match in EMAIL_RE.finditer(text):
        yield match.group(0)
    for match in AT_OBFUSCATION_RE.finditer(text):
        yield f"{match.group(1)}@{match.group(2)}"


def extract_mailtos(html: str) -> Iterable[str]:
    mailto_re = re.compile(r'href=["\']mailto:([^"\']+)["\']', re.IGNORECASE)
    for match in mailto_re.finditer(html):
        raw = match.group(1).split("?")[0]
        yield raw.strip()


def extract_phones(visible_text: str, html: str) -> set:
    phones = set()
    for match in PHONE_LINK_RE.finditer(html):
        phone = match.group(1).strip()
        if len(phone) >= 8:
            phones.add(phone)
    for match in PHONE_RE.finditer(visible_text):
        phone = match.group(0).strip()
        if len(phone.replace(" ", "").replace("-", "").replace(".", "")) >= 8:
            phones.add(phone)
    return phones


def is_valid_email(email: str) -> bool:
    email = email.strip().lower()
    if email in BAD_EMAIL_VALUES or "@" not in email:
        return False
    local, domain = email.rsplit("@", 1)
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in BAD_EMAIL_TLDS or domain in BAD_EMAIL_DOMAINS:
        return False
    if any(frag in domain for frag in BAD_DOMAIN_FRAGMENTS):
        return False
    if email.startswith(EXCLUDED_PREFIXES):
        return False
    return True


def pick_primary_email(candidates: List[str], site_base_domain: str) -> Optional[str]:
    valid = [e for e in candidates if is_valid_email(e)]
    if not valid:
        return None

    priority = []
    non_free = []
    free = []

    for e in valid:
        domain = e.split("@")[1].lower()
        if e.lower().startswith(PRIORITY_PREFIXES):
            priority.append(e)
        elif domain not in FREE_MAIL_PROVIDERS:
            non_free.append(e)
        else:
            free.append(e)

    # Prioriteer: priority prefix + matching domain > priority > non-free > free
    for bucket in [priority, non_free, free]:
        for e in bucket:
            domain = e.split("@")[1].lower()
            if domain == site_base_domain:
                return e
        if bucket:
            return bucket[0]

    return valid[0]


def check_page_flags(html: str, visible_text: str) -> PageFlags:
    lower = visible_text.lower()
    flags = PageFlags()
    for p in MALWARE_PATTERNS:
        if p in lower:
            flags.isMalware = True
            break
    for p in MAINTENANCE_PATTERNS:
        if p in lower:
            flags.isMaintenance = True
            break
    for p in UNCONNECTED_DOMAIN_PATTERNS:
        if p in lower:
            flags.isUnconnected = True
            break
    for p in SITE_UNAVAILABLE_PATTERNS:
        if p in lower:
            flags.isUnavailable = True
            break
    return flags


async def block_heavy_resources(route: Route, request: Request):
    if request.resource_type in ["image", "media", "font", "stylesheet"]:
        await route.abort()
    else:
        await route.continue_()


def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def get_base_domain(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc or parsed.path
    parts = netloc.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else netloc


def generate_urls(base_url: str) -> List[str]:
    """Genereer URLs om te scannen — geoptimaliseerd voor snelheid."""
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    combined = f"{scheme}://{netloc.rstrip('/')}"

    urls = [combined + "/"]  # Homepage eerst

    # Contact pagina's (hoogste prioriteit voor email)
    for path in CONTACT_PATHS:
        urls.append(urljoin(combined, path))

    # Fallback pagina's (alleen als contact geen email oplevert)
    for path in FALLBACK_PATHS:
        urls.append(urljoin(combined, path))

    # Dedup
    seen = set()
    return [u for u in urls if u not in seen and not seen.add(u)]


async def scrape_site(page: Page, lead: Lead, timeout_ms: int) -> Dict[str, Any]:
    url = normalize_url(lead.website)
    if not url:
        return {"isReachable": False, "discardReason": "invalid_url", "primaryEmail": None, "phone": None}

    Actor.log.info(f"[SCRAPE] {lead.name}: {url}")

    site_base = get_base_domain(url)
    urls_to_try = generate_urls(url)

    all_emails = set()
    all_phones = set()
    any_success = False
    http_error_status = None

    page.set_default_navigation_timeout(timeout_ms)
    page.set_default_timeout(timeout_ms)

    for url_to_visit in urls_to_try:
        try:
            response = await page.goto(url_to_visit, wait_until="domcontentloaded")

            if response:
                status = response.status
                if 200 <= status < 300:
                    any_success = True
                elif 400 <= status < 600:
                    if http_error_status is None:
                        http_error_status = status
                    continue

            html = await page.content()
            visible = await page.inner_text("body")

            flags = check_page_flags(html, visible)

            if flags.isMalware:
                return {"isReachable": False, "discardReason": "malware", "primaryEmail": None, "phone": None}
            if flags.isUnavailable:
                continue
            if (flags.isMaintenance or flags.isUnconnected):
                # Check of er toch een email op staat
                temp = set(collect_emails_from_text(visible)) | set(extract_mailtos(html)) | set(collect_emails_from_html(html))
                if not temp:
                    continue

            # Extract emails
            for e in collect_emails_from_text(visible):
                all_emails.add(e)
            for e in extract_mailtos(html):
                all_emails.add(e)
            for e in collect_emails_from_html(html):
                all_emails.add(e)

            # Extract phones
            for p in extract_phones(visible, html):
                all_phones.add(p)

            # Early exit: als we een goede email hebben, stop direct
            primary = pick_primary_email(sorted(all_emails), site_base)
            if primary and not primary.split("@")[1] in FREE_MAIL_PROVIDERS:
                phone = list(all_phones)[0] if all_phones else lead.phone
                Actor.log.info(f"[FOUND] {lead.name}: {primary} (early exit)")
                return {"isReachable": True, "discardReason": None, "primaryEmail": primary, "phone": phone}

        except Exception:
            continue

    # Eindresultaat
    if not any_success and http_error_status is None:
        return {"isReachable": False, "discardReason": "unreachable", "primaryEmail": None, "phone": None}

    if http_error_status and not any_success:
        return {"isReachable": False, "discardReason": "http_error", "primaryEmail": None, "phone": None, "httpErrorStatus": http_error_status}

    primary = pick_primary_email(sorted(all_emails), site_base) if all_emails else None
    phone = list(all_phones)[0] if all_phones else lead.phone

    if not primary and not phone:
        return {"isReachable": True, "discardReason": "no_contact_info", "primaryEmail": None, "phone": None}

    return {"isReachable": True, "discardReason": None, "primaryEmail": primary, "phone": phone}


async def main():
    async with Actor:
        input_data = await Actor.get_input() or {}

        leads_raw = input_data.get("leadsJson", []) or []

        if isinstance(leads_raw, str):
            import json
            try:
                leads_raw = json.loads(leads_raw)
            except json.JSONDecodeError:
                leads_raw = []

        concurrency = clamp_int(input_data.get("concurrency"), 1, 50, default=10)
        timeout_ms = clamp_int(input_data.get("perSiteTimeoutSec"), 3, 15, default=5) * 1000
        hard_timeout = clamp_int(input_data.get("perLeadHardTimeoutSec"), 10, 60, default=25)

        # Parse leads
        leads: List[Lead] = []
        for l in (leads_raw if isinstance(leads_raw, list) else []):
            if not isinstance(l, dict):
                continue
            lead_id = l.get("leadId") or l.get("id") or l.get("placeId")
            website = l.get("website") or l.get("url")
            if not lead_id or not website:
                continue
            leads.append(Lead(
                lead_id=str(lead_id),
                website=str(website),
                name=l.get("name"),
                phone=l.get("phone") or l.get("phoneNumber"),
                city=l.get("city") or l.get("municipality"),
                address=l.get("address") or l.get("fullAddress"),
            ))

        Actor.log.info(f"[START] {len(leads)} leads to process (concurrency: {concurrency})")

        sem = asyncio.Semaphore(concurrency)

        async with async_playwright() as p:
            browser: Browser = await p.chromium.launch(
                headless=True,
                args=["--disable-gpu", "--disable-dev-shm-usage", "--disable-extensions",
                      "--disable-background-networking", "--disable-background-timer-throttling"],
            )

            context = await browser.new_context(java_script_enabled=False)
            await context.route("**/*", block_heavy_resources)

            async def process_lead(lead: Lead) -> Optional[Dict[str, Any]]:
                async with sem:
                    page = await context.new_page()
                    try:
                        result = await asyncio.wait_for(
                            scrape_site(page, lead, timeout_ms),
                            timeout=hard_timeout,
                        )
                    except asyncio.TimeoutError:
                        Actor.log.warning(f"[TIMEOUT] {lead.lead_id} ({lead.website})")
                        return None
                    except Exception as e:
                        Actor.log.error(f"[ERROR] {lead.lead_id}: {e}")
                        return None
                    finally:
                        await page.close()

                reason = result.get("discardReason")
                if reason in ("invalid_url", "unreachable", "malware", "http_error"):
                    Actor.log.info(f"[SKIP] {lead.lead_id}: {reason}")
                    return None

                return {
                    "leadId": lead.lead_id,
                    "website": lead.website,
                    "name": lead.name,
                    "city": lead.city,
                    "address": lead.address,
                    "primaryEmail": result.get("primaryEmail"),
                    "phone": result.get("phone"),
                    "isReachable": result.get("isReachable"),
                    "discardReason": reason,
                }

            tasks = [asyncio.create_task(process_lead(l)) for l in leads]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            batch = [r for r in results if isinstance(r, dict)]

            Actor.log.info(f"[DONE] Input: {len(leads)}, Output: {len(batch)}")

            await Actor.set_value("OUTPUT", batch, content_type="application/json")

            if batch:
                for i in range(0, len(batch), 200):
                    await Actor.push_data(batch[i:i + 200])

            await context.close()
            try:
                await asyncio.wait_for(browser.close(), timeout=10)
            except asyncio.TimeoutError:
                pass

        await Actor.exit()


if __name__ == "__main__":
    asyncio.run(main())
