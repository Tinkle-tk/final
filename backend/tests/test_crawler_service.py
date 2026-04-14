from types import SimpleNamespace

import os

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from app import create_app
from app.extensions import db
from app.services.crawler_service import crawl_and_ingest
from app.crawlers.discovery import assess_document_relevance, extract_candidate_links


class FakeResponse:
    def __init__(self, url, text='', content=b'', content_type='text/html'):
        self.url = url
        self.text = text
        self.content = content or text.encode('utf-8')
        self.headers = {'Content-Type': content_type}

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self, responses):
        self.responses = responses

    def get(self, url, headers=None, timeout=20):
        return self.responses[url]


def test_crawl_and_ingest_follows_candidate_links(monkeypatch):
    html = """
    <html>
      <head><title>Security Center</title></head>
      <body>
        <a href="/advisory-1.html">Vendor Advisory</a>
        <a href="/manual.pdf">Manual PDF</a>
      </body>
    </html>
    """
    advisory = """
    <html>
      <head><title>Advisory 1</title></head>
      <body>CVE-2024-12345 affects firmware v4.5.1. Patch ID: FIX-001.</body>
    </html>
    """
    session = FakeSession(
        {
            'https://example.com/security': FakeResponse('https://example.com/security', text=html),
            'https://example.com/advisory-1.html': FakeResponse(
                'https://example.com/advisory-1.html',
                text=advisory,
            ),
            'https://example.com/manual.pdf': FakeResponse(
                'https://example.com/manual.pdf',
                content=b'%PDF-1.4',
                content_type='application/pdf',
            ),
        }
    )

    monkeypatch.setattr(
        'app.services.crawler_service.document_from_response',
        lambda response, source_url=None: SimpleNamespace(
            final_url=response.url,
            title='title',
            content_type=response.headers['Content-Type'],
            text='CVE-2024-12345 Patch ID: FIX-001',
        ),
    )

    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
        result = crawl_and_ingest(
            start_url='https://example.com/security',
            extractor_mode='rule',
            session=session,
            max_depth=1,
            max_pages=5,
        )

    assert result['pages_crawled'] == 3
    assert result['documents_processed'] == 3
    assert result['records'] >= 2


def test_extract_candidate_links_uses_broader_security_signals():
    html = """
    <html>
      <body>
        <a href="/detail/123">WordPress plugin Verge3D Publishing and E-Commerce 代码注入漏洞</a>
        <a href="/about">About us</a>
      </body>
    </html>
    """

    links = extract_candidate_links(html, 'https://example.com/index.html', allowed_domain='example.com')

    assert len(links) == 1
    assert links[0]['url'] == 'https://example.com/detail/123'


def test_assess_document_relevance_requires_more_than_navigation_copy():
    relevance = assess_document_relevance(
        text='欢迎访问产品中心，请登录后查看。',
        title='产品中心',
        url='https://example.com/product',
        content_type='text/html',
    )

    assert relevance['should_ingest'] is False
