from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from typing import Any

import requests

from ..extractors.hybrid_extractor import extract_records
from ..extractors.nlp_extractor import ParsedRecord
from .ingestion_service import upsert_record


CNNVD_BASE_URL = 'https://www.cnnvd.org.cn/web/'
CNNVD_LIST_ENDPOINT = 'homePage/cnnvdVulList'
CNNVD_DETAIL_ENDPOINT = 'cnnvdVul/getCnnnvdDetailOnDatasource'
CNNVD_SOURCE_URL_TEMPLATE = (
    'https://www.cnnvd.org.cn/web/cnnvdVul/getCnnnvdDetailOnDatasource?cnnvdCode={cnnvd_code}'
)

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; ICS-Vuln-KB/1.0)',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Referer': 'https://www.cnnvd.org.cn/home/child',
}

INDUSTRIAL_VENDOR_KEYWORDS = (
    'abb',
    'advantech',
    'allen-bradley',
    'beckhoff',
    'bently nevada',
    'bosch rexroth',
    'emerson',
    'ge',
    'hirschmann',
    'honeywell',
    'moxa',
    'omron',
    'openplc',
    'phoenix contact',
    'rockwell',
    'schneider',
    'siemens',
    'wago',
    'yokogawa',
    '三菱',
    '万可',
    '倍福',
    '台达',
    '和利时',
    '施耐德',
    '横河',
    '欧姆龙',
    '研华',
    '罗克韦尔',
    '艾默生',
    '菲尼克斯',
    '西门子',
    '霍尼韦尔',
)

INDUSTRIAL_ASSET_KEYWORDS = (
    'bacnet',
    'controller',
    'dcs',
    'ethernet/ip',
    'firmware',
    'gateway',
    'hmi',
    'ics',
    'industrial',
    'modbus',
    'opc ua',
    'openplc',
    'ot',
    'pac',
    'plc',
    'profinet',
    'rtu',
    'scada',
    'workstation',
    '上位机',
    '人机界面',
    '仪表',
    '交换机',
    '可编程逻辑控制器',
    '固件',
    '工业',
    '工控',
    '控制器',
    '控制系统',
    '网关',
)
HIGH_CONFIDENCE_ASSET_KEYWORDS = (
    'dcs',
    'firmware',
    'hmi',
    'ics',
    'industrial',
    'modbus',
    'openplc',
    'opc ua',
    'ot',
    'plc',
    'profinet',
    'rtu',
    'scada',
    '上位机',
    '人机界面',
    '固件',
    '工业',
    '工控',
    '控制系统',
)

FIRMWARE_SIGNAL_KEYWORDS = (
    'firmware',
    'patch',
    'upgrade',
    'version',
    '固件',
    '升级',
    '版本',
    '补丁',
)

NEGATIVE_KEYWORDS = (
    'blog',
    'cms',
    'e-commerce',
    'forum',
    'library',
    'online course',
    'school',
    'shopping',
    'wordpress',
    '商城',
    '博客',
    '教务',
    '课程',
)

TRAILING_VULNERABILITY_SUFFIX = re.compile(
    r'\s*(?:安全)?(?:命令注入|代码注入|SQL注入|缓冲区溢出|拒绝服务|权限提升|信息泄露|路径遍历|身份验证绕过)?漏洞$',
    re.IGNORECASE,
)
VERSION_TOKEN_PATTERN = re.compile(r'(?:v|version|firmware)\s*[:=]?\s*([A-Za-z0-9][A-Za-z0-9_.-]{1,40})', re.IGNORECASE)
PATCH_ID_PATTERN = re.compile(r'\b(?:KB[- ]?\d{5,8}|[A-Z]{2,12}[-_][A-Z0-9_-]*\d+[A-Z0-9_-]*)\b')
SHORT_VERSION_PATTERN = re.compile(r'^[vV]?\d+(?:\.\d+){0,4}[A-Za-z0-9-]*$')
EMBEDDED_VERSION_PATTERN = re.compile(r'\bv(\d+(?:\.\d+){0,4}[A-Za-z0-9-]*)\b', re.IGNORECASE)


@dataclass(slots=True)
class CNNVDSummary:
    id: str
    cnnvd_code: str
    cve_code: str | None
    vul_name: str
    hazard_level: int | None
    publish_time: str | None
    vul_type: str | None

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> 'CNNVDSummary':
        return cls(
            id=str(payload.get('id', '')).strip(),
            cnnvd_code=str(payload.get('cnnvdCode', '')).strip(),
            cve_code=_clean_text(payload.get('cveCode')),
            vul_name=str(payload.get('vulName', '')).strip(),
            hazard_level=_safe_int(payload.get('hazardLevel')),
            publish_time=_clean_text(payload.get('publishTime')),
            vul_type=_clean_text(payload.get('vulType')),
        )


class CNNVDClient:
    def __init__(self, session: requests.Session | None = None, timeout: int = 20):
        self.session = session or requests.Session()
        if hasattr(self.session, 'trust_env'):
            self.session.trust_env = False
        self.timeout = timeout

    def list_vulnerabilities(self, page_index: int, page_size: int = 50) -> dict[str, Any]:
        response = self.session.post(
            CNNVD_BASE_URL + CNNVD_LIST_ENDPOINT,
            json={'pageIndex': page_index, 'pageSize': min(max(page_size, 1), 50)},
            headers=DEFAULT_HEADERS,
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not payload.get('success'):
            raise RuntimeError(f'CNNVD list request failed: {payload.get("message")}')
        return payload

    def get_detail(self, summary: CNNVDSummary) -> dict[str, Any]:
        response = self.session.post(
            CNNVD_BASE_URL + CNNVD_DETAIL_ENDPOINT,
            json={
                'id': summary.id,
                'vulType': summary.vul_type or '0',
                'cnnvdCode': summary.cnnvd_code,
            },
            headers=DEFAULT_HEADERS,
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not payload.get('success'):
            raise RuntimeError(f'CNNVD detail request failed for {summary.cnnvd_code}: {payload.get("message")}')
        return payload


def import_cnnvd_industrial_vulnerabilities(
    *,
    start_page: int = 1,
    end_page: int | None = None,
    page_size: int = 50,
    title_threshold: int = 1,
    detail_threshold: int = 4,
    extractor_mode: str = 'rule',
    max_imports: int | None = None,
    sleep_seconds: float = 0.0,
    dry_run: bool = False,
    client: CNNVDClient | None = None,
) -> dict[str, Any]:
    cnnvd = client or CNNVDClient()
    page_index = max(1, start_page)
    total_pages: int | None = None

    scanned = 0
    title_hits = 0
    detail_hits = 0
    imported = 0
    inserted = 0
    updated = 0
    errors: list[dict[str, str]] = []
    matched: list[dict[str, Any]] = []

    while True:
        if end_page is not None and page_index > end_page:
            break
        if total_pages is not None and page_index > total_pages:
            break
        if max_imports is not None and imported >= max_imports:
            break

        page_payload = cnnvd.list_vulnerabilities(page_index=page_index, page_size=page_size)
        data = page_payload.get('data') or {}
        total = _safe_int(data.get('total')) or 0
        total_pages = max(1, math.ceil(total / min(max(page_size, 1), 50)))
        records = data.get('records') or []
        if not records:
            break

        for raw_summary in records:
            scanned += 1
            summary = CNNVDSummary.from_api(raw_summary)
            title_score = score_cnnvd_industrial_relevance(summary)
            if title_score < title_threshold:
                continue

            title_hits += 1
            try:
                detail_payload = cnnvd.get_detail(summary)
                detail = _extract_detail_payload(detail_payload)
                detail_score = score_cnnvd_industrial_relevance(summary, detail)
                if detail_score < detail_threshold:
                    continue

                detail_hits += 1
                match_info = {
                    'cnnvd_code': summary.cnnvd_code,
                    'vul_name': summary.vul_name,
                    'title_score': title_score,
                    'detail_score': detail_score,
                }
                matched.append(match_info)

                if dry_run:
                    imported += 1
                    if max_imports is not None and imported >= max_imports:
                        break
                    continue

                result = ingest_cnnvd_detail(
                    summary=summary,
                    detail=detail,
                    extractor_mode=extractor_mode,
                )
                imported += 1
                inserted += result['inserted']
                updated += result['updated']

                if max_imports is not None and imported >= max_imports:
                    break
                if sleep_seconds > 0:
                    time.sleep(sleep_seconds)
            except Exception as exc:  # pragma: no cover - exercised by runtime failures
                errors.append({'cnnvd_code': summary.cnnvd_code, 'error': str(exc)})

        page_index += 1

    return {
        'start_page': start_page,
        'end_page': end_page if end_page is not None else total_pages,
        'total_pages': total_pages,
        'records_scanned': scanned,
        'title_hits': title_hits,
        'detail_hits': detail_hits,
        'imported': imported,
        'inserted': inserted,
        'updated': updated,
        'dry_run': dry_run,
        'matched': matched,
        'errors': errors,
    }


def ingest_cnnvd_detail(
    *,
    summary: CNNVDSummary,
    detail: dict[str, Any],
    extractor_mode: str = 'rule',
) -> dict[str, Any]:
    hints = build_cnnvd_hints(summary, detail)
    extraction_text = build_cnnvd_extraction_text(summary, detail)
    extracted_records, resolved_mode = extract_records(
        text=extraction_text,
        hints=hints,
        extractor_mode=extractor_mode,
    )
    base_record = extracted_records[0] if extracted_records else None

    patch_ids = _merge_unique(
        [],
        _split_structured_patch_ids(detail),
    )
    versions = _merge_unique(
        _split_versions(detail.get('version')),
        _extract_explicit_versions(summary.vul_name, detail.get('vulDesc'), detail.get('patch')),
    )
    description = build_cnnvd_storage_description(summary, detail)
    disclosure_date = _normalize_publish_date(detail.get('publishTime') or summary.publish_time)
    vuln_type = _clean_text(detail.get('vulTypeName')) or _clean_text(detail.get('vulType')) or (
        base_record.vuln_type if base_record else None
    )

    record = ParsedRecord(
        cve_id=summary.cnnvd_code,
        description=description,
        cvss_score=base_record.cvss_score if base_record else None,
        disclosure_date=disclosure_date,
        vuln_type=vuln_type,
        vendor=hints.get('vendor'),
        series=hints.get('series'),
        model=hints.get('model'),
        versions=versions,
        patch_ids=patch_ids,
        upgrade_path=_clean_text(detail.get('patch')) or (base_record.upgrade_path if base_record else None),
    )

    _, created = upsert_record(
        record,
        source_url=CNNVD_SOURCE_URL_TEMPLATE.format(cnnvd_code=summary.cnnvd_code),
    )
    return {
        'cnnvd_code': summary.cnnvd_code,
        'inserted': 1 if created else 0,
        'updated': 0 if created else 1,
        'extractor_mode': resolved_mode,
        'vendor': record.vendor,
        'model': record.model,
    }


def score_cnnvd_industrial_relevance(summary: CNNVDSummary, detail: dict[str, Any] | None = None) -> int:
    values = [summary.vul_name]
    if detail:
        values.extend(
            [
                detail.get('affectedVendor'),
                detail.get('affectedProduct'),
                detail.get('affectedSystem'),
                detail.get('productDesc'),
                detail.get('vulDesc'),
                detail.get('patch'),
                detail.get('version'),
            ]
        )
    text = ' '.join(_clean_text(value) or '' for value in values).lower()
    if not text:
        return 0

    score = 0
    vendor_hits = sum(1 for keyword in INDUSTRIAL_VENDOR_KEYWORDS if _contains_keyword(text, keyword))
    asset_hits = sum(1 for keyword in INDUSTRIAL_ASSET_KEYWORDS if _contains_keyword(text, keyword))
    strong_asset_hits = sum(1 for keyword in HIGH_CONFIDENCE_ASSET_KEYWORDS if _contains_keyword(text, keyword))
    firmware_hits = sum(1 for keyword in FIRMWARE_SIGNAL_KEYWORDS if _contains_keyword(text, keyword))

    score += min(vendor_hits * 3, 9)
    score += min(asset_hits * 2, 8)
    score += min(firmware_hits, 3)
    score -= min(sum(1 for keyword in NEGATIVE_KEYWORDS if _contains_keyword(text, keyword)) * 2, 4)

    if detail and (_clean_text(detail.get('affectedProduct')) or _clean_text(detail.get('affectedSystem'))):
        score += 1
    if vendor_hits == 0 and strong_asset_hits == 0:
        score = min(score, 3)

    return score


def build_cnnvd_hints(summary: CNNVDSummary, detail: dict[str, Any]) -> dict[str, str]:
    vendor = _clean_text(detail.get('affectedVendor')) or _clean_text(detail.get('vendorName'))
    model = _clean_text(detail.get('affectedProduct')) or infer_model_from_title(summary.vul_name)
    hints: dict[str, str] = {}
    if vendor:
        hints['vendor'] = vendor
    if model:
        hints['model'] = model
    return hints


def build_cnnvd_extraction_text(summary: CNNVDSummary, detail: dict[str, Any]) -> str:
    lines = [
        f'CNNVD编号: {summary.cnnvd_code}',
        f'漏洞名称: {summary.vul_name}',
        f'漏洞类型: {_clean_text(detail.get("vulTypeName")) or _clean_text(detail.get("vulType")) or ""}',
        f'厂商: {_clean_text(detail.get("affectedVendor")) or ""}',
        f'产品: {_clean_text(detail.get("affectedProduct")) or ""}',
        f'系统: {_clean_text(detail.get("affectedSystem")) or ""}',
        f'版本: {_clean_text(detail.get("version")) or ""}',
        f'漏洞描述: {_clean_text(detail.get("vulDesc")) or ""}',
        f'补丁编号: {_clean_text(detail.get("patchId")) or ""}',
        f'修复建议: {_clean_text(detail.get("patch")) or ""}',
        f'参考信息: {_clean_text(detail.get("referUrl")) or ""}',
    ]
    return '\n'.join(line for line in lines if not line.endswith(': '))


def build_cnnvd_storage_description(summary: CNNVDSummary, detail: dict[str, Any]) -> str:
    lines = [
        f'CNNVD编号: {summary.cnnvd_code}',
        f'CVE编号: {summary.cve_code}' if summary.cve_code else '',
        f'漏洞名称: {summary.vul_name}',
        f'披露时间: {_normalize_publish_date(detail.get("publishTime") or summary.publish_time) or ""}',
        f'受影响厂商: {_clean_text(detail.get("affectedVendor")) or ""}',
        f'受影响产品: {_clean_text(detail.get("affectedProduct")) or ""}',
        f'受影响系统: {_clean_text(detail.get("affectedSystem")) or ""}',
        f'漏洞描述: {_clean_text(detail.get("vulDesc")) or ""}',
        f'参考信息: {_clean_text(detail.get("referUrl")) or ""}',
    ]
    return '\n'.join(line for line in lines if line and not line.endswith(': '))


def infer_model_from_title(vul_name: str) -> str | None:
    cleaned = _clean_text(vul_name)
    if not cleaned:
        return None
    cleaned = TRAILING_VULNERABILITY_SUFFIX.sub('', cleaned).strip(' -:')
    return cleaned or None


def _extract_detail_payload(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get('data') or {}
    return data.get('cnnvdDetail') or data.get('receviceVulDetail') or {}


def _normalize_publish_date(value: str | None) -> str | None:
    text = _clean_text(value)
    if not text:
        return None
    return text.split(' ', 1)[0]


def _split_structured_patch_ids(detail: dict[str, Any]) -> list[str]:
    values = [_clean_text(detail.get('patchId'))]
    patch_text = _clean_text(detail.get('patch'))
    if patch_text:
        values.extend(match.group(0) for match in PATCH_ID_PATTERN.finditer(patch_text))
    return _merge_unique([], [value for value in values if value])


def _split_versions(value: Any) -> list[str]:
    text = _clean_text(value)
    if not text:
        return []
    if SHORT_VERSION_PATTERN.fullmatch(text):
        return [text.lstrip('vV')]
    matches = [item.group(1) for item in VERSION_TOKEN_PATTERN.finditer(text)]
    matches.extend(item.group(1) for item in EMBEDDED_VERSION_PATTERN.finditer(text))
    return _merge_unique([], matches)


def _merge_unique(left: list[str], right: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for item in [*left, *right]:
        normalized = str(item).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).replace('\r', '\n')
    text = re.sub(r'\n{2,}', '\n', text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = text.strip()
    return text or None


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _contains_keyword(text: str, keyword: str) -> bool:
    lowered_keyword = keyword.lower()
    if any('\u4e00' <= ch <= '\u9fff' for ch in lowered_keyword):
        return lowered_keyword in text
    if re.fullmatch(r'[a-z0-9][a-z0-9 ./_-]*', lowered_keyword):
        pattern = rf'(?<![a-z0-9]){re.escape(lowered_keyword)}(?![a-z0-9])'
        return re.search(pattern, text) is not None
    return lowered_keyword in text


def _extract_explicit_versions(*values: Any) -> list[str]:
    versions: list[str] = []
    for value in values:
        versions.extend(_split_versions(value))
    return _merge_unique([], versions)
