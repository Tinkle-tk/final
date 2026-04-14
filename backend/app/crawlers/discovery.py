from __future__ import annotations

import re
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup


ADVISORY_KEYWORDS = (
    'advisory',
    'alert',
    'bulletin',
    'cve',
    'cnnvd',
    'cnvd',
    'cvss',
    'firmware',
    'fix',
    'hotfix',
    'injection',
    'patch',
    'remediation',
    'rce',
    'security',
    'upgrade',
    'vuln',
    'vulnerability',
    'xss',
    '公告',
    '升级',
    '漏洞',
    '预警',
    '补丁',
    '通报',
    '修复',
    '.pdf',
)

NEGATIVE_KEYWORDS = (
    'about',
    'contact',
    'login',
    'policy',
    'privacy',
    'register',
    'signin',
    'terms',
)

ID_PATTERN = re.compile(r'\b(?:CVE|CNNVD|CNVD)\s*[-_]?\s*\d{4,8}\s*[-_]?\s*\d{3,8}\b', re.IGNORECASE)
SECURITY_SIGNAL_PATTERN = re.compile(
    r'\b(?:cve|cnnvd|cnvd|cvss|firmware|vulnerability|security|advisory|patch|upgrade|hotfix|injection|rce|xss)\b|漏洞|通报|公告|预警|补丁|修复|升级|代码注入|命令注入|拒绝服务',
    re.IGNORECASE,
)


def normalize_url(url: str) -> str:
    clean, _fragment = urldefrag(url.strip())
    return clean


def is_pdf_url(url: str, content_type: str = '') -> bool:
    lowered_url = url.lower()
    lowered_type = content_type.lower()
    return lowered_url.endswith('.pdf') or 'application/pdf' in lowered_type


def looks_like_advisory_link(url: str, text: str = '') -> bool:
    return score_advisory_candidate(url=url, text=text) >= 2


def score_advisory_candidate(url: str, text: str = '', context: str = '') -> int:
    haystack = f'{url} {text} {context}'.lower()
    score = 0

    if is_pdf_url(url):
        score += 2

    keyword_hits = sum(1 for keyword in ADVISORY_KEYWORDS if keyword in haystack)
    score += min(keyword_hits, 4)
    if keyword_hits:
        score += 1

    if ID_PATTERN.search(haystack):
        score += 4

    if keyword_hits == 0 and any(keyword in haystack for keyword in NEGATIVE_KEYWORDS):
        score -= 2

    return score


def assess_document_relevance(
    text: str,
    title: str = '',
    url: str = '',
    content_type: str = '',
) -> dict[str, int | bool]:
    haystack = f'{title} {url} {text}'
    score = score_advisory_candidate(url=url, text=title, context=text[:1200])

    id_hits = len(ID_PATTERN.findall(haystack))
    signal_hits = len(SECURITY_SIGNAL_PATTERN.findall(haystack[:3000]))

    score += min(id_hits * 3, 9)
    score += min(signal_hits // 3, 4)

    if len(text.strip()) < 80:
        score -= 2

    return {
        'score': score,
        'id_hits': id_hits,
        'signal_hits': signal_hits,
        'should_ingest': id_hits > 0 or score >= 4 or is_pdf_url(url, content_type),
    }


def extract_candidate_links(
    html: str,
    base_url: str,
    allowed_domain: str | None = None,
) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, 'html.parser')
    results: list[dict[str, str | int]] = []
    seen: set[str] = set()

    for anchor in soup.select('a[href]'):
        href = (anchor.get('href') or '').strip()
        if not href:
            continue

        absolute_url = normalize_url(urljoin(base_url, href))
        if not absolute_url.startswith(('http://', 'https://')):
            continue

        parsed = urlparse(absolute_url)
        if allowed_domain and parsed.netloc != allowed_domain:
            continue

        label = anchor.get_text(' ', strip=True)
        parent_text = ''
        if anchor.parent and anchor.parent.name not in {'body', 'html'}:
            parent_text = anchor.parent.get_text(' ', strip=True)[:200]
        score = score_advisory_candidate(url=absolute_url, text=label, context=parent_text)
        if score < 2:
            continue

        if absolute_url in seen:
            continue

        seen.add(absolute_url)
        results.append({'url': absolute_url, 'label': label, 'score': score})

    results.sort(key=lambda item: (-int(item['score']), str(item['url'])))
    return results
