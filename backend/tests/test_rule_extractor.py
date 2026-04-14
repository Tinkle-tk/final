from app.extractors.nlp_extractor import parse_document_text


def test_rule_extractor_handles_cve_date_patch_and_version():
    text = (
        'Advisory: CVE 2024 77777 affects PLC firmware version 4.5.1. '
        '披露日期 2024年7月1日, CVSS v3.1 Base Score: 9.8. '
        '补丁编号: PATCH-2024-01, 建议升级到 4.5.3.'
    )
    rows = parse_document_text(text)
    assert len(rows) == 1
    r = rows[0]
    assert r.cve_id == 'CVE-2024-77777'
    assert r.disclosure_date == '2024-07-01'
    assert r.cvss_score == 9.8
    assert '4.5.1' in r.versions
    assert 'PATCH-2024-01' in r.patch_ids
    assert r.upgrade_path is not None


def test_rule_extractor_maps_vuln_type():
    text = 'CVE-2025-12345 allows remote code execution via command injection in web component.'
    rows = parse_document_text(text)
    assert len(rows) == 1
    assert rows[0].vuln_type in {'rce', 'command_injection'}


def test_rule_extractor_handles_cnnvd_ids():
    text = 'WordPress plugin 漏洞编号 CNNVD-202312-2479，存在代码注入漏洞。'
    rows = parse_document_text(text)
    assert len(rows) == 1
    assert rows[0].cve_id == 'CNNVD-202312-2479'


def test_rule_extractor_splits_long_documents_by_neighboring_ids():
    text = (
        '本期重要漏洞实例 1. CNNVD-202312-2479 WordPress plugin Verge3D Publishing and E-Commerce '
        '4.5.2版本及之前版本存在代码注入漏洞，攻击者可以远程执行代码。 '
        '2. CNNVD-202312-2286 Apache OFBiz 存在代码问题漏洞，可导致远程代码执行。'
    )

    rows = parse_document_text(text)

    assert len(rows) == 2
    first = next(item for item in rows if item.cve_id == 'CNNVD-202312-2479')
    second = next(item for item in rows if item.cve_id == 'CNNVD-202312-2286')
    assert 'WordPress plugin' in first.description
    assert 'Apache OFBiz' not in first.description
    assert 'Apache OFBiz' in second.description
