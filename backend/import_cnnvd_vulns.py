from __future__ import annotations

import argparse
import json

from app import create_app
from app.extensions import db
from app.services.cnnvd_bulk_import_service import import_cnnvd_industrial_vulnerabilities


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Bulk import industrial-control-related CNNVD vulnerabilities into the local knowledge base.',
    )
    parser.add_argument('--start-page', type=int, default=1, help='CNNVD list page to start from.')
    parser.add_argument('--end-page', type=int, default=None, help='CNNVD list page to stop at.')
    parser.add_argument('--page-size', type=int, default=50, help='Requested CNNVD page size, capped at 50 by the API.')
    parser.add_argument('--title-threshold', type=int, default=1, help='Minimum title score before fetching detail.')
    parser.add_argument('--detail-threshold', type=int, default=4, help='Minimum full-detail relevance score to import.')
    parser.add_argument('--extractor-mode', default='rule', choices=['rule', 'hybrid', 'llm', 'auto'])
    parser.add_argument('--max-imports', type=int, default=None, help='Stop after importing this many matched records.')
    parser.add_argument('--sleep-seconds', type=float, default=0.0, help='Delay between successful imports.')
    parser.add_argument('--dry-run', action='store_true', help='Only scan and score CNNVD data, do not write database records.')
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        db.create_all()
        result = import_cnnvd_industrial_vulnerabilities(
            start_page=args.start_page,
            end_page=args.end_page,
            page_size=args.page_size,
            title_threshold=args.title_threshold,
            detail_threshold=args.detail_threshold,
            extractor_mode=args.extractor_mode,
            max_imports=args.max_imports,
            sleep_seconds=args.sleep_seconds,
            dry_run=args.dry_run,
        )
        if not args.dry_run:
            db.session.commit()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
