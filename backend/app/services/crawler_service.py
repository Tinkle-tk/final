from __future__ import annotations

from collections import deque
from typing import Any
from urllib.parse import urlparse

import requests

from ..crawlers.discovery import assess_document_relevance, extract_candidate_links, is_pdf_url, normalize_url
from .document_ingestion_service import DEFAULT_REQUEST_HEADERS, document_from_response
from .ingestion_service import ingest_text_document


def crawl_and_ingest(
    start_url: str,
    hints: dict[str, Any] | None = None,
    extractor_mode: str | None = None,
    max_depth: int = 1,
    max_pages: int = 10,
    session: requests.Session | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    client = session or requests.Session()
    root_url = normalize_url(start_url)
    allowed_domain = urlparse(root_url).netloc

    queue: deque[tuple[str, int]] = deque([(root_url, 0)])
    visited: set[str] = set()
    documents: list[dict[str, Any]] = []
    total_records = 0
    total_inserted = 0
    total_updated = 0

    while queue and len(visited) < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited:
            continue

        visited.add(current_url)

        try:
            response = client.get(current_url, headers=DEFAULT_REQUEST_HEADERS, timeout=timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            documents.append(
                {
                    'url': current_url,
                    'depth': depth,
                    'status': 'error',
                    'error': str(exc),
                    'records': 0,
                    'inserted': 0,
                    'updated': 0,
                }
            )
            continue

        candidate_links = []
        is_html = 'html' in response.headers.get('Content-Type', '').lower() or not is_pdf_url(current_url)
        if is_html:
            candidate_links = extract_candidate_links(response.text, current_url, allowed_domain=allowed_domain)

        document = document_from_response(response, source_url=current_url)
        relevance = assess_document_relevance(
            text=document.text,
            title=document.title or '',
            url=document.final_url,
            content_type=document.content_type,
        )

        result: dict[str, Any] | None = None
        if relevance['should_ingest']:
            result = ingest_text_document(
                text=document.text,
                hints=hints,
                extractor_mode=extractor_mode,
                source_url=document.final_url,
            )
            total_records += result['records']
            total_inserted += result['inserted']
            total_updated += result['updated']

        documents.append(
            {
                'url': document.final_url,
                'title': document.title,
                'content_type': document.content_type,
                'depth': depth,
                'status': 'ingested' if result is not None else 'skipped',
                'relevance_score': relevance['score'],
                'records': result['records'] if result else 0,
                'inserted': result['inserted'] if result else 0,
                'updated': result['updated'] if result else 0,
                'extractor_mode': result['extractor_mode'] if result else None,
            }
        )

        if depth >= max_depth or is_pdf_url(document.final_url, document.content_type):
            continue

        for candidate in candidate_links:
            candidate_url = normalize_url(candidate['url'])
            if candidate_url in visited:
                continue
            queue.append((candidate_url, depth + 1))

    successful_docs = [item for item in documents if item['status'] == 'ingested']
    return {
        'start_url': root_url,
        'pages_crawled': len(visited),
        'documents_processed': len(successful_docs),
        'records': total_records,
        'inserted': total_inserted,
        'updated': total_updated,
        'documents': documents,
    }
