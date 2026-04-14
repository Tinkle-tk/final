from app.extractors.hybrid_extractor import extract_records
from app.extractors.nlp_extractor import ParsedRecord


def test_rule_mode_extracts_cve():
    records, mode = extract_records('Device has CVE-2024-12345 and CVSS 8.1', extractor_mode='rule')
    assert mode == 'rule'
    assert any(r.cve_id == 'CVE-2024-12345' for r in records)


def test_hybrid_falls_back_to_rule_when_llm_empty(monkeypatch):
    monkeypatch.setattr('app.extractors.hybrid_extractor.parse_with_llm', lambda text, hints: [])
    records, mode = extract_records('CVE-2025-8888 in firmware v1.2.3', extractor_mode='hybrid')
    assert mode == 'rule'
    assert len(records) >= 1


def test_hybrid_merges_llm_fields(monkeypatch):
    def fake_llm(_text, _hints):
        return [
            ParsedRecord(
                cve_id='CVE-2024-12345',
                description='llm desc',
                vuln_type='command injection',
                versions=['4.5.1'],
                patch_ids=['PATCH-1'],
            )
        ]

    monkeypatch.setattr('app.extractors.hybrid_extractor.parse_with_llm', fake_llm)
    records, mode = extract_records('CVE-2024-12345', extractor_mode='hybrid')

    assert mode == 'hybrid'
    assert records[0].cve_id == 'CVE-2024-12345'
    assert records[0].description == 'llm desc'
    assert 'PATCH-1' in records[0].patch_ids
