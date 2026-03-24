from __future__ import annotations

import html
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List

from bs4 import BeautifulSoup


WHOIS_BASE_URL = "https://cctld.uz/whois/"
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


@dataclass
class DomainWhoisInfo:
    domain: str = ""
    www: str = ""
    status: str = ""
    registrar: str = ""
    created_date: str = ""
    expiry_date: str = ""
    ns_servers: List[str] = field(default_factory=list)
    source_url: str = ""

    def ns_joined(self) -> str:
        return "\n".join(item for item in self.ns_servers if item)


def _clean_text(value: str) -> str:
    text = html.unescape(str(value or ""))
    text = text.replace("\xa0", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _decode_html(raw: bytes) -> str:
    head = raw[:4000].decode("ascii", errors="ignore")
    match = re.search(r"charset=['\"]?([A-Za-z0-9._-]+)", head, re.I)
    candidates = []
    if match:
        candidates.append(match.group(1))
    candidates.extend(["utf-8", "cp1251", "windows-1251", "latin-1"])
    for encoding in candidates:
        try:
            return raw.decode(encoding)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def fetch_whois_html(domain: str, zone: str = "uz", timeout: int = 20) -> str:
    query = urllib.parse.urlencode({"domain": domain, "zone": zone})
    url = f"{WHOIS_BASE_URL}?{query}"
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return _decode_html(resp.read())


def parse_whois_tbody(raw_html: str, source_url: str = "") -> DomainWhoisInfo:
    info = DomainWhoisInfo(source_url=source_url)
    soup = BeautifulSoup(raw_html or "", "html.parser")
    tbody = soup.find("tbody")
    if not tbody:
        return info

    for row in tbody.find_all("tr"):
        cells = row.find_all("td")
        if not cells:
            continue

        left_label = _clean_text(cells[0].get_text(" ", strip=True)) if len(cells) >= 1 else ""
        left_value = _clean_text(cells[1].get_text(" ", strip=True)) if len(cells) >= 2 else ""
        right_label = ""
        right_value = ""
        if len(cells) >= 6:
            right_label = _clean_text(cells[4].get_text(" ", strip=True))
            right_value = _clean_text(cells[5].get_text(" ", strip=True))
        elif len(cells) >= 4:
            right_label = _clean_text(cells[2].get_text(" ", strip=True))
            right_value = _clean_text(cells[3].get_text(" ", strip=True))

        label_l = left_label.lower()
        right_l = right_label.lower()

        if "домен" in label_l or "domen" in label_l:
            links = cells[1].find_all("a") if len(cells) >= 2 else []
            if links:
                if len(links) >= 1:
                    info.domain = _clean_text(links[0].get_text(" ", strip=True))
                if len(links) >= 2:
                    info.www = _clean_text(links[1].get_text(" ", strip=True))
            if not info.domain and left_value:
                match = re.search(r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})", left_value)
                if match:
                    info.domain = match.group(1)

        if "ҳолати" in label_l or "holati" in label_l or "status" in label_l:
            info.status = left_value

        if "рўйхатдан ўтказувчи" in label_l or "registrator" in label_l:
            info.registrar = left_value

        if "рўйхатдан ўтган сана" in label_l or "yaratilgan sana" in label_l:
            info.created_date = re.sub(r"\s*г\.\s*$", "", left_value).strip()

        if "фаолияти тугайди" in label_l or "yaroqlilik muddati" in label_l:
            info.expiry_date = re.sub(r"\s*г\.\s*$", "", left_value).strip()

        if "ns" in right_l and right_value and "not.defined" not in right_value.lower():
            cleaned_ns = re.sub(r"^\s*домен:\s*", "", right_value, flags=re.I)
            info.ns_servers.append(cleaned_ns.strip())

    if not info.www and info.domain:
        info.www = f"www.{info.domain}"
    return info


def lookup_domain_info(domain: str, zone: str = "uz", timeout: int = 20) -> DomainWhoisInfo:
    query = urllib.parse.urlencode({"domain": domain, "zone": zone})
    source_url = f"{WHOIS_BASE_URL}?{query}"
    try:
        raw_html = fetch_whois_html(domain=domain, zone=zone, timeout=timeout)
        return parse_whois_tbody(raw_html, source_url=source_url)
    except Exception:
        return DomainWhoisInfo(domain=domain, www=f"www.{domain}", source_url=source_url)
