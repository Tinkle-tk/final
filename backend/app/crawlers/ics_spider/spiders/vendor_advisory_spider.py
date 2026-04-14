from urllib.parse import urlparse

import scrapy

from ...discovery import extract_candidate_links, is_pdf_url, looks_like_advisory_link


class VendorAdvisorySpider(scrapy.Spider):
    name = 'vendor_advisory'
    allowed_domains = []
    start_urls = []

    custom_settings = {
        'FEED_EXPORT_ENCODING': 'utf-8',
    }

    def __init__(self, start_url: str | None = None, max_depth: int = 1, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_depth = max(0, int(max_depth))
        if start_url:
            self.start_urls = [start_url]
            domain = urlparse(start_url).netloc
            self.allowed_domains = [domain] if domain else []

    def parse(self, response):
        depth = response.meta.get('depth', 0)
        content_type = response.headers.get('Content-Type', b'').decode('utf-8', errors='ignore')
        title = response.css('title::text').get()

        if is_pdf_url(response.url, content_type) or looks_like_advisory_link(response.url, title or ''):
            yield {
                'source_page': response.request.headers.get(b'Referer', b'').decode('utf-8', errors='ignore')
                or response.url,
                'advisory_url': response.url,
                'title': title,
                'content_type': content_type,
            }

        if depth >= self.max_depth or is_pdf_url(response.url, content_type):
            return

        allowed_domain = self.allowed_domains[0] if self.allowed_domains else None
        for candidate in extract_candidate_links(response.text, response.url, allowed_domain=allowed_domain):
            yield response.follow(
                candidate['url'],
                callback=self.parse,
                meta={'depth': depth + 1},
                headers={'Referer': response.url},
            )
