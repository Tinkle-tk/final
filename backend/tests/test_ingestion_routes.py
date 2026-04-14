import io
import os

import pytest

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from app import create_app
from app.extensions import db


@pytest.fixture()
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.drop_all()
        db.create_all()
    return app.test_client()


def test_ingest_url_route(client, monkeypatch):
    def fake_ingest_url_document(url, hints=None, extractor_mode=None):
        assert url == 'https://example.com/advisory'
        assert hints == {'vendor': 'Siemens'}
        assert extractor_mode == 'rule'
        return {
            'records': 1,
            'inserted': 1,
            'updated': 0,
            'extractor_mode': 'rule',
            'source_type': 'url',
            'source_url': url,
        }

    monkeypatch.setattr('app.routes.vulnerabilities.ingest_url_document', fake_ingest_url_document)

    response = client.post(
        '/vulnerabilities/ingest/url',
        json={
            'url': 'https://example.com/advisory',
            'extractor_mode': 'rule',
            'hints': {'vendor': 'Siemens'},
        },
    )

    assert response.status_code == 201
    data = response.get_json()
    assert data['records'] == 1
    assert data['source_url'] == 'https://example.com/advisory'


def test_ingest_file_route(client, monkeypatch):
    def fake_ingest_uploaded_file(filename, file_bytes, content_type='', hints=None, extractor_mode=None):
        assert filename == 'advisory.txt'
        assert file_bytes.decode('utf-8') == 'CVE-2024-12345'
        assert content_type == 'text/plain'
        assert hints == {'vendor': 'Siemens'}
        assert extractor_mode == 'rule'
        return {
            'records': 1,
            'inserted': 1,
            'updated': 0,
            'extractor_mode': 'rule',
            'filename': filename,
        }

    monkeypatch.setattr('app.routes.vulnerabilities.ingest_uploaded_file', fake_ingest_uploaded_file)

    response = client.post(
        '/vulnerabilities/ingest/file',
        data={
            'extractor_mode': 'rule',
            'vendor': 'Siemens',
            'file': (io.BytesIO(b'CVE-2024-12345'), 'advisory.txt', 'text/plain'),
        },
        content_type='multipart/form-data',
    )

    assert response.status_code == 201
    data = response.get_json()
    assert data['filename'] == 'advisory.txt'


def test_crawl_route(client, monkeypatch):
    def fake_crawl_and_ingest(start_url, hints=None, extractor_mode=None, max_depth=1, max_pages=10):
        assert start_url == 'https://example.com/security'
        assert hints == {'vendor': 'Siemens'}
        assert extractor_mode == 'hybrid'
        assert max_depth == 2
        assert max_pages == 5
        return {
            'start_url': start_url,
            'pages_crawled': 3,
            'documents_processed': 2,
            'records': 2,
            'inserted': 2,
            'updated': 0,
            'documents': [],
        }

    monkeypatch.setattr('app.routes.vulnerabilities.crawl_and_ingest', fake_crawl_and_ingest)

    response = client.post(
        '/vulnerabilities/crawl',
        json={
            'url': 'https://example.com/security',
            'extractor_mode': 'hybrid',
            'max_depth': 2,
            'max_pages': 5,
            'hints': {'vendor': 'Siemens'},
        },
    )

    assert response.status_code == 201
    data = response.get_json()
    assert data['pages_crawled'] == 3
