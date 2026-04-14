from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

from ..extractors.document_parser import extract_text_from_html, extract_text_from_pdf, extract_text_from_pdf_bytes
from .ingestion_service import ingest_text_document


DEFAULT_REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; ICS-Vuln-KB/1.0)',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
}


@dataclass
class RetrievedDocument:
    source_url: str
    final_url: str
    content_type: str
    text: str
    title: str | None = None


def ingest_file_path(
    file_path: str | Path,
    hints: dict[str, Any] | None = None,
    extractor_mode: str | None = None,
) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f'File not found: {path}')

    suffix = path.suffix.lower()
    if suffix == '.pdf':
        text = extract_text_from_pdf(path)
        content_type = 'application/pdf'
    elif suffix in {'.html', '.htm'}:
        text = extract_text_from_html(path.read_text(encoding='utf-8', errors='ignore'))
        content_type = 'text/html'
    else:
        text = path.read_text(encoding='utf-8', errors='ignore')
        content_type = 'text/plain'

    result = ingest_text_document(text=text, hints=hints, extractor_mode=extractor_mode, source_url=str(path))
    result.update({'source_type': 'file', 'filename': path.name, 'content_type': content_type})
    return result


def ingest_uploaded_file(
    filename: str,
    file_bytes: bytes,
    content_type: str = '',
    hints: dict[str, Any] | None = None,
    extractor_mode: str | None = None,
) -> dict[str, Any]:
    text, resolved_content_type = extract_text_from_upload(filename, file_bytes, content_type)
    result = ingest_text_document(
        text=text,
        hints=hints,
        extractor_mode=extractor_mode,
        source_url=f'upload://{filename}',
    )
    result.update({'source_type': 'upload', 'filename': filename, 'content_type': resolved_content_type})
    return result


def ingest_url_document(
    url: str,
    hints: dict[str, Any] | None = None,
    extractor_mode: str | None = None,
    session: requests.Session | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    document = fetch_document_from_url(url, session=session, timeout=timeout)
    result = ingest_text_document(
        text=document.text,
        hints=hints,
        extractor_mode=extractor_mode,
        source_url=document.final_url,
    )
    result.update(
        {
            'source_type': 'url',
            'source_url': document.final_url,
            'content_type': document.content_type,
            'title': document.title,
        }
    )
    return result


def fetch_document_from_url(
    url: str,
    session: requests.Session | None = None,
    timeout: int = 20,
) -> RetrievedDocument:
    client = session or requests.Session()
    response = client.get(url, headers=DEFAULT_REQUEST_HEADERS, timeout=timeout)
    response.raise_for_status()
    return document_from_response(response, source_url=url)


def document_from_response(response: requests.Response, source_url: str | None = None) -> RetrievedDocument:
    content_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
    source = source_url or response.url

    if _is_pdf_document(response.url, content_type):
        text = extract_text_from_pdf_bytes(response.content)
        return RetrievedDocument(
            source_url=source,
            final_url=response.url,
            content_type=content_type or 'application/pdf',
            text=text,
            title=Path(response.url).name or None,
        )

    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.get_text(strip=True) if soup.title else None
    return RetrievedDocument(
        source_url=source,
        final_url=response.url,
        content_type=content_type or 'text/html',
        text=extract_text_from_html(html),
        title=title,
    )


def extract_text_from_upload(filename: str, file_bytes: bytes, content_type: str = '') -> tuple[str, str]:
    resolved_type = (content_type or '').split(';', 1)[0].strip().lower()
    lower_name = filename.lower()

    if lower_name.endswith('.pdf') or 'application/pdf' in resolved_type:
        return extract_text_from_pdf_bytes(file_bytes), 'application/pdf'

    if lower_name.endswith(('.html', '.htm')) or 'text/html' in resolved_type:
        html = file_bytes.decode('utf-8', errors='ignore')
        return extract_text_from_html(html), 'text/html'

    text = file_bytes.decode('utf-8', errors='ignore')
    return text, resolved_type or 'text/plain'


def _is_pdf_document(url: str, content_type: str) -> bool:
    lowered_url = url.lower()
    lowered_type = content_type.lower()
    return lowered_url.endswith('.pdf') or 'application/pdf' in lowered_type
