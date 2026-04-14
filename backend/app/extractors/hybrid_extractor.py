from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .llm_extractor import parse_with_llm
from .nlp_extractor import ParsedRecord, parse_document_text


def extract_records(
    text: str,
    hints: dict[str, Any] | None = None,
    extractor_mode: str = 'hybrid',
) -> tuple[list[ParsedRecord], str]:
    hints = hints or {}
    mode = (extractor_mode or 'hybrid').lower()

    if mode == 'rule':
        return parse_document_text(text, hints), 'rule'

    if mode == 'llm':
        return parse_with_llm(text, hints), 'llm'

    if mode in {'hybrid', 'auto'}:
        rule_records = parse_document_text(text, hints)
        llm_records = parse_with_llm(text, hints)
        merged = _merge_records(rule_records, llm_records)
        if llm_records:
            return merged, 'hybrid'
        return rule_records, 'rule'

    return parse_document_text(text, hints), 'rule'


def _merge_records(rule_records: list[ParsedRecord], llm_records: list[ParsedRecord]) -> list[ParsedRecord]:
    if not llm_records:
        return rule_records
    if not rule_records:
        return llm_records

    by_cve: OrderedDict[str, ParsedRecord] = OrderedDict()

    for item in rule_records:
        by_cve[item.cve_id] = item

    for llm_item in llm_records:
        current = by_cve.get(llm_item.cve_id)
        if current is None:
            by_cve[llm_item.cve_id] = llm_item
            continue

        by_cve[llm_item.cve_id] = ParsedRecord(
            cve_id=current.cve_id,
            description=llm_item.description or current.description,
            cvss_score=llm_item.cvss_score if llm_item.cvss_score is not None else current.cvss_score,
            disclosure_date=llm_item.disclosure_date or current.disclosure_date,
            vuln_type=llm_item.vuln_type or current.vuln_type,
            vendor=llm_item.vendor or current.vendor,
            series=llm_item.series or current.series,
            model=llm_item.model or current.model,
            versions=sorted(set(current.versions + llm_item.versions)),
            patch_ids=sorted(set(current.patch_ids + llm_item.patch_ids)),
            upgrade_path=llm_item.upgrade_path or current.upgrade_path,
        )

    return list(by_cve.values())
