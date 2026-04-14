from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pdfplumber
from bs4 import BeautifulSoup


def extract_text_from_pdf(path: str | Path) -> str:
    with pdfplumber.open(path) as pdf:
        return _extract_text_from_pdf_document(pdf)


def extract_text_from_pdf_bytes(raw_pdf: bytes) -> str:
    with pdfplumber.open(BytesIO(raw_pdf)) as pdf:
        return _extract_text_from_pdf_document(pdf)


def extract_text_from_html(raw_html: str) -> str:
    soup = BeautifulSoup(raw_html, 'html.parser')
    for tag in soup(['script', 'style', 'noscript']):
        tag.extract()
    return soup.get_text('\n', strip=True)


def _extract_text_from_pdf_document(pdf: pdfplumber.PDF) -> str:
    pages: list[str] = []
    for page in pdf.pages:
        pages.append(page.extract_text() or '')
    return '\n'.join(pages)
