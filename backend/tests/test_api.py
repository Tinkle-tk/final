import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from app import create_app
from app.extensions import db
from app.models import Patch, Vulnerability


@pytest.fixture()
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.drop_all()
        db.create_all()
        v = Vulnerability(cve_id='CVE-2024-0001', description='test vuln', cvss_score=8.8)
        db.session.add(v)
        db.session.add(Patch(cve_id='CVE-2024-0001', patch_id='PATCH-001', upgrade_path='upgrade to 1.0.2'))
        db.session.commit()
    return app.test_client()


def test_query_vulnerabilities(client):
    resp = client.get('/vulnerabilities?cve_id=CVE-2024-0001')
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]['cve_id'] == 'CVE-2024-0001'


def test_related_patches(client):
    resp = client.get('/vulnerabilities/CVE-2024-0001/related_patches')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['cve_id'] == 'CVE-2024-0001'
    assert data['patches'][0]['patch_id'] == 'PATCH-001'
