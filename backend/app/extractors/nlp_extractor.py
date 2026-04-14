import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


CVE_PATTERN = re.compile(r'CVE\s*[-_]?\s*(\d{4})\s*[-_]?\s*(\d{4,7})', re.IGNORECASE)
CNNVD_PATTERN = re.compile(r'CNNVD\s*[-_]?\s*(\d{6})\s*[-_]?\s*(\d{3,})', re.IGNORECASE)

CVSS_PATTERNS = [
    re.compile(r'base\s*score[^\d]{0,8}(10(?:\.0)?|[0-9](?:\.\d)?)', re.IGNORECASE),
    re.compile(r'评分[^\d]{0,8}(10(?:\.0)?|[0-9](?:\.\d)?)', re.IGNORECASE),
    re.compile(
        r'CVSS(?:\s*v(?:2|3(?:\.0|\.1)?))?[^\d]{0,20}(10(?:\.0)?|[0-9](?:\.\d)?)',
        re.IGNORECASE,
    ),
]

VERSION_PATTERNS = [
    re.compile(r'\b(?:v|ver|version|fw|firmware)\s*[:=]?\s*(\d+(?:\.\d+){1,4}[a-zA-Z0-9-]*)\b', re.IGNORECASE),
    re.compile(r'\b\d+(?:\.\d+){1,4}(?:-[A-Za-z0-9]+)?\b'),
    re.compile(r'\bR\d+(?:\.\d+){1,3}\b', re.IGNORECASE),
    re.compile(r'\bbuild\s*[:=]?\s*([A-Za-z0-9_.-]+)\b', re.IGNORECASE),
]

DATE_PATTERNS = [
    re.compile(r'\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b'),
    re.compile(r'\b(20\d{2})\.(\d{1,2})\.(\d{1,2})\b'),
    re.compile(r'\b(20\d{2})年(\d{1,2})月(\d{1,2})日\b'),
    re.compile(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(\d{1,2}),?\s+(20\d{2})\b', re.IGNORECASE),
]

PATCH_PATTERNS = [
    re.compile(r'补丁(?:编号|ID|号)?[:：\s]+([A-Za-z0-9_.-]+)', re.IGNORECASE),
    re.compile(r'patch(?:\s*id|\s*number)?[:：\s]+([A-Za-z0-9_.-]+)', re.IGNORECASE),
    re.compile(r'hotfix[:：\s]+([A-Za-z0-9_.-]+)', re.IGNORECASE),
    re.compile(r'kb[-\s]?(\d{5,8})', re.IGNORECASE),
    re.compile(r'security\s*update[:：\s]+([A-Za-z0-9_.-]+)', re.IGNORECASE),
    re.compile(r'升级包[:：\s]+([A-Za-z0-9_.-]+)', re.IGNORECASE),
    re.compile(r'修复包[:：\s]+([A-Za-z0-9_.-]+)', re.IGNORECASE),
]

UPGRADE_PATH_PATTERNS = [
    re.compile(r'(?:升级(?:到|至)|update\s*to|upgrade\s*to)\s*([A-Za-z0-9_.-]+)', re.IGNORECASE),
    re.compile(r'(?:建议|recommend(?:ed)?)\s*(?:升级|update|upgrade)[^\n\r]{0,100}', re.IGNORECASE),
]

VULN_TYPE_RULES = {
    'buffer_overflow': [
        'buffer overflow', 'stack overflow', 'heap overflow', '缓冲区溢出', '堆溢出', '栈溢出',
    ],
    'command_injection': [
        'command injection', 'os command injection', '命令注入', '系统命令注入',
    ],
    'sql_injection': [
        'sql injection', 'sqli', 'sql注入',
    ],
    'xss': [
        'cross-site scripting', 'xss', '跨站脚本',
    ],
    'rce': [
        'remote code execution', 'arbitrary code execution', 'rce', '远程代码执行',
    ],
    'dos': [
        'denial of service', 'dos', '拒绝服务',
    ],
    'privilege_escalation': [
        'privilege escalation', 'elevation of privilege', '权限提升',
    ],
    'auth_bypass': [
        'authentication bypass', 'auth bypass', '认证绕过', '身份验证绕过',
    ],
    'path_traversal': [
        'path traversal', 'directory traversal', '../', '路径穿越', '目录遍历',
    ],
    'file_inclusion': [
        'file inclusion', 'lfi', 'rfi', '文件包含',
    ],
    'ssrf': [
        'server-side request forgery', 'ssrf',
    ],
    'csrf': [
        'cross-site request forgery', 'csrf', '跨站请求伪造',
    ],
    'info_disclosure': [
        'information disclosure', 'sensitive information', '信息泄露', '敏感信息泄露',
    ],
    'hardcoded_credentials': [
        'hard-coded credential', 'hardcoded password', '硬编码口令', '默认口令',
    ],
    'deserialization': [
        'unsafe deserialization', 'insecure deserialization', '反序列化',
    ],
    'memory_corruption': [
        'memory corruption', '内存破坏',
    ],
}


@dataclass
class ParsedRecord:
    cve_id: str
    description: str
    cvss_score: float | None = None
    disclosure_date: str | None = None
    vuln_type: str | None = None
    vendor: str | None = None
    series: str | None = None
    model: str | None = None
    versions: list[str] = field(default_factory=list)
    patch_ids: list[str] = field(default_factory=list)
    upgrade_path: str | None = None


def parse_document_text(text: str, hints: dict[str, Any] | None = None) -> list[ParsedRecord]:
    hints = hints or {}
    normalized = _normalize_text(text)
    matches = _find_vulnerability_matches(normalized)
    if not matches:
        return []

    parsed: list[ParsedRecord] = []
    seen_ids: set[str] = set()
    for index, (vuln_id, start, end) in enumerate(matches):
        if vuln_id in seen_ids:
            continue
        seen_ids.add(vuln_id)
        snippet = _find_context(normalized, matches, index)
        cvss_score = _extract_cvss(snippet)
        parsed.append(
            ParsedRecord(
                cve_id=vuln_id,
                description=snippet,
                cvss_score=cvss_score,
                disclosure_date=_extract_date(snippet),
                vuln_type=_infer_vuln_type(snippet),
                vendor=hints.get('vendor'),
                series=hints.get('series'),
                model=hints.get('model'),
                versions=_extract_versions(snippet, cvss_score=cvss_score),
                patch_ids=_extract_patch_ids(snippet),
                upgrade_path=_extract_upgrade_path(snippet) or hints.get('upgrade_path'),
            )
        )

    return parsed


def _normalize_text(text: str) -> str:
    s = unicodedata.normalize('NFKC', text or '')
    trans = str.maketrans({
        '：': ':', '；': ';', '，': ',', '。': '.', '（': '(', '）': ')',
        '【': '[', '】': ']', '—': '-', '–': '-', '－': '-', '／': '/',
    })
    s = s.translate(trans)
    s = re.sub(r'\s+', ' ', s)
    return s.strip()


def _extract_vuln_ids(text: str) -> list[str]:
    return [item[0] for item in _find_vulnerability_matches(text)]


def _find_vulnerability_matches(text: str) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    ids: list[str] = []
    for m in CVE_PATTERN.finditer(text):
        vuln_id = f'CVE-{m.group(1)}-{m.group(2)}'
        ids.append(vuln_id)
        matches.append((vuln_id, m.start(), m.end()))
    for m in CNNVD_PATTERN.finditer(text):
        vuln_id = f'CNNVD-{m.group(1)}-{m.group(2)}'
        ids.append(vuln_id)
        matches.append((vuln_id, m.start(), m.end()))
    matches.sort(key=lambda item: item[1])
    return matches


def _find_context(
    text: str,
    matches: list[tuple[str, int, int]],
    current_index: int,
    before_window: int = 260,
    after_window: int = 520,
) -> str:
    keyword, start_idx, end_idx = matches[current_index]
    prev_end = matches[current_index - 1][2] if current_index > 0 else 0
    next_start = matches[current_index + 1][1] if current_index + 1 < len(matches) else len(text)

    start = max(prev_end, start_idx - before_window)
    end = min(next_start, end_idx + after_window)

    snippet = text[start:end].strip()
    if len(snippet) < 120:
        fallback_start = max(0, start_idx - 380)
        fallback_end = min(len(text), end_idx + 640)
        snippet = text[fallback_start:fallback_end].strip()

    sentence_bounded = _trim_to_boundaries(snippet, keyword)
    return sentence_bounded or snippet


def _trim_to_boundaries(text: str, keyword: str) -> str:
    idx = text.lower().find(keyword.lower())
    if idx < 0:
        return text.strip()

    boundary_chars = '.;:!?。！？；:'
    start = 0
    for pos in range(idx, max(-1, idx - 220), -1):
        if text[pos] in boundary_chars:
            start = pos + 1
            break

    end = len(text)
    for pos in range(idx, min(len(text), idx + 700)):
        if text[pos] in boundary_chars:
            end = pos + 1
            if end - start >= 80:
                break

    trimmed = text[start:end].strip()
    return trimmed if trimmed else text.strip()


def _extract_cvss(text: str) -> float | None:
    for pattern in CVSS_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        try:
            score = float(m.group(1))
            if 0 <= score <= 10:
                return score
        except ValueError:
            continue
    return None


def _extract_date(text: str) -> str | None:
    for pattern in DATE_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        try:
            if pattern is DATE_PATTERNS[3]:
                raw = m.group(0)
                try:
                    return datetime.strptime(raw, '%b %d, %Y').date().isoformat()
                except ValueError:
                    return datetime.strptime(raw, '%B %d, %Y').date().isoformat()
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            return datetime(year=y, month=mo, day=d).date().isoformat()
        except ValueError:
            continue
    return None


def _extract_versions(text: str, cvss_score: float | None = None) -> list[str]:
    versions: set[str] = set()
    for pattern in VERSION_PATTERNS:
        for m in pattern.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            val = val.strip().lstrip('vV')
            if not val:
                continue
            if re.fullmatch(r'\d{4}', val):
                continue
            if cvss_score is not None and val == f'{cvss_score:.1f}':
                continue
            versions.add(val)
    return sorted(versions)


def _infer_vuln_type(text: str) -> str | None:
    lowered = text.lower()
    for canonical, keywords in VULN_TYPE_RULES.items():
        if any(k.lower() in lowered for k in keywords):
            return canonical
    return None


def _extract_patch_ids(text: str) -> list[str]:
    ids: set[str] = set()
    for pattern in PATCH_PATTERNS:
        for m in pattern.finditer(text):
            val = (m.group(1) if m.lastindex else m.group(0)).strip()
            if val:
                ids.add(val)
    return sorted(ids)


def _extract_upgrade_path(text: str) -> str | None:
    for pattern in UPGRADE_PATH_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0).strip()
    return None
