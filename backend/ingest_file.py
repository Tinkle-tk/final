from __future__ import annotations

import argparse

from app import create_app
from app.services.document_ingestion_service import ingest_file_path


def main() -> None:
    parser = argparse.ArgumentParser(description='Ingest ICS advisory file into MySQL KB')
    parser.add_argument('--file', required=True, help='Path to html/pdf/txt file')
    parser.add_argument('--vendor', help='Vendor name')
    parser.add_argument('--series', help='Product series')
    parser.add_argument('--model', help='Product model')
    parser.add_argument('--upgrade-path', help='Upgrade path description')
    parser.add_argument(
        '--extractor-mode',
        default='hybrid',
        choices=['hybrid', 'llm', 'rule', 'auto'],
        help='Information extraction mode',
    )
    args = parser.parse_args()

    hints = {
        'vendor': args.vendor,
        'series': args.series,
        'model': args.model,
        'upgrade_path': args.upgrade_path,
    }

    app = create_app()
    with app.app_context():
        result = ingest_file_path(args.file, hints=hints, extractor_mode=args.extractor_mode)
        print(result)


if __name__ == '__main__':
    main()
