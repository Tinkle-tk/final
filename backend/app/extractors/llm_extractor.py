import json
import os
import re
from typing import Any

from .nlp_extractor import ParsedRecord


_CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)


def parse_with_llm(text: str, hints: dict[str, Any] | None = None) -> list[ParsedRecord]:
    hints = hints or {}
    api_key = os.getenv('LLM_API_KEY')
    model = os.getenv('LLM_MODEL', 'gpt-4.1-mini')
    base_url = os.getenv('LLM_BASE_URL')

    if not api_key:
        return []

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            temperature=0,
            response_format={'type': 'json_object'},
            messages=[
                {
                    'role': 'system',
                    'content': (
                        'You extract ICS firmware vulnerability records from unstructured text. '
                        'Return strict JSON with key "records" as an array. '
                        'Each item keys: cve_id, description, cvss_score, disclosure_date, '
                        'vuln_type, vendor, series, model, versions, patch_ids, upgrade_path.'
                    ),
                },
                {
                    'role': 'user',
                    'content': json.dumps({'text': text, 'hints': hints}, ensure_ascii=False),
                },
            ],
        )

        payload = response.choices[0].message.content or '{}'
        raw = json.loads(payload)
        records = raw.get('records', []) if isinstance(raw, dict) else []
        return _normalize_records(records, hints)
    except Exception:
        return []


def _normalize_records(items: list[dict[str, Any]], hints: dict[str, Any]) -> list[ParsedRecord]:
    normalized: list[ParsedRecord] = []
    for item in items:
        cve_id = str(item.get('cve_id', '')).upper().strip()
        if not _CVE_PATTERN.match(cve_id):
            continue

        versions = item.get('versions') or []
        patch_ids = item.get('patch_ids') or []
        if not isinstance(versions, list):
            versions = []
        if not isinstance(patch_ids, list):
            patch_ids = []

        cvss_score = item.get('cvss_score')
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None

        normalized.append(
            ParsedRecord(
                cve_id=cve_id,
                description=str(item.get('description') or '').strip() or cve_id,
                cvss_score=cvss_score,
                disclosure_date=_as_date_str(item.get('disclosure_date')),
                vuln_type=_as_str(item.get('vuln_type')),
                vendor=_as_str(item.get('vendor')) or hints.get('vendor'),
                series=_as_str(item.get('series')) or hints.get('series'),
                model=_as_str(item.get('model')) or hints.get('model'),
                versions=[str(v).lstrip('vV') for v in versions if str(v).strip()],
                patch_ids=[str(p).strip() for p in patch_ids if str(p).strip()],
                upgrade_path=_as_str(item.get('upgrade_path')) or hints.get('upgrade_path'),
            )
        )
    return normalized


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _as_date_str(value: Any) -> str | None:
    if value is None:
        return None
    raw = str(value).strip().replace('/', '-')
    if re.match(r'^\d{4}-\d{2}-\d{2}$', raw):
        return raw
    return None
