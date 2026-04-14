import os

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from app import create_app
from app.extensions import db
from app.models import FirmwareVersion, Patch, Product, Vulnerability
from app.services.cnnvd_bulk_import_service import (
    CNNVDClient,
    CNNVDSummary,
    import_cnnvd_industrial_vulnerabilities,
    score_cnnvd_industrial_relevance,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, list_payloads, detail_payloads):
        self.list_payloads = list_payloads
        self.detail_payloads = detail_payloads
        self.trust_env = False

    def post(self, url, json=None, headers=None, timeout=20):
        if url.endswith('homePage/cnnvdVulList'):
            page_index = json['pageIndex']
            return FakeResponse(self.list_payloads[page_index])
        if url.endswith('cnnvdVul/getCnnnvdDetailOnDatasource'):
            cnnvd_code = json['cnnvdCode']
            return FakeResponse(self.detail_payloads[cnnvd_code])
        raise AssertionError(f'unexpected url: {url}')


def test_score_cnnvd_industrial_relevance_prefers_plc_signals():
    summary = CNNVDSummary(
        id='abc',
        cnnvd_code='CNNVD-202604-2121',
        cve_code='CVE-2024-1490',
        vul_name='WAGO PLC 代码注入漏洞',
        hazard_level=2,
        publish_time='2026-04-09',
        vul_type='0',
    )
    detail = {
        'affectedVendor': '万可',
        'affectedProduct': 'PLC',
        'vulDesc': 'WAGO PLC 是一款可编程逻辑控制器，存在固件命令执行风险。',
        'patch': 'Upgrade to v4.5.2 or later.',
    }

    assert score_cnnvd_industrial_relevance(summary) >= 3
    assert score_cnnvd_industrial_relevance(summary, detail) >= 6


def test_import_cnnvd_industrial_vulnerabilities_imports_relevant_records():
    list_payloads = {
        1: {
            'success': True,
            'data': {
                'total': 2,
                'records': [
                    {
                        'id': 'rel-1',
                        'cnnvdCode': 'CNNVD-202604-2121',
                        'cveCode': 'CVE-2024-1490',
                        'vulName': 'WAGO PLC 固件命令注入漏洞',
                        'hazardLevel': 2,
                        'publishTime': '2026-04-09',
                        'vulType': '0',
                    },
                    {
                        'id': 'skip-1',
                        'cnnvdCode': 'CNNVD-202604-3000',
                        'cveCode': 'CVE-2026-0001',
                        'vulName': 'Online Course Registration SQL注入漏洞',
                        'hazardLevel': 2,
                        'publishTime': '2026-04-09',
                        'vulType': '0',
                    },
                ],
            },
        }
    }
    detail_payloads = {
        'CNNVD-202604-2121': {
            'success': True,
            'data': {
                'cnnvdDetail': {
                    'vulName': 'WAGO PLC 固件命令注入漏洞',
                    'cnnvdCode': 'CNNVD-202604-2121',
                    'cveCode': 'CVE-2024-1490',
                    'publishTime': '2026-04-09 00:00:00',
                    'vulType': '命令注入',
                    'vulTypeName': '命令注入',
                    'vulDesc': 'WAGO PLC firmware v4.5.1 suffers command injection. Upgrade to v4.5.2 or later.',
                    'affectedVendor': 'WAGO',
                    'affectedProduct': 'PLC',
                    'affectedSystem': '',
                    'patchId': 'WAGO-001',
                    'patch': 'Upgrade to v4.5.2 or later.',
                    'version': 'v4.5.1',
                    'referUrl': 'https://example.com/advisory',
                }
            },
        }
    }

    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        result = import_cnnvd_industrial_vulnerabilities(
            start_page=1,
            end_page=1,
            extractor_mode='rule',
            client=CNNVDClient(session=FakeSession(list_payloads, detail_payloads)),
        )
        db.session.commit()

        vulnerability = Vulnerability.query.filter_by(cve_id='CNNVD-202604-2121').first()
        product = Product.query.filter_by(vendor='WAGO', model='PLC').first()
        firmware = FirmwareVersion.query.filter_by(version_number='4.5.1').first()
        patch = Patch.query.filter_by(cve_id='CNNVD-202604-2121', patch_id='WAGO-001').first()

        assert result['imported'] == 1
        assert result['inserted'] == 1
        assert result['updated'] == 0
        assert vulnerability is not None
        assert product is not None
        assert firmware is not None
        assert patch is not None
