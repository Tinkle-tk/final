import requests
from flask import Blueprint, jsonify, request

from ..models import AffectedFirmware, FirmwareVersion, Patch, Product, Vulnerability
from ..services.crawler_service import crawl_and_ingest
from ..services.document_ingestion_service import ingest_uploaded_file, ingest_url_document
from ..services.ingestion_service import ingest_text_document

vulnerabilities_bp = Blueprint('vulnerabilities', __name__, url_prefix='/vulnerabilities')


@vulnerabilities_bp.get('')
def query_vulnerabilities():
    cve_id = request.args.get('cve_id')
    product_name = request.args.get('product_name')
    vendor = request.args.get('vendor')

    query = Vulnerability.query

    if cve_id:
        query = query.filter(Vulnerability.cve_id.ilike(f'%{cve_id}%'))

    if product_name or vendor:
        query = query.join(AffectedFirmware, AffectedFirmware.vulnerability_id == Vulnerability.id)
        query = query.join(FirmwareVersion, FirmwareVersion.id == AffectedFirmware.firmware_version_id)
        query = query.join(Product, Product.id == FirmwareVersion.product_id)

        if product_name:
            query = query.filter(Product.model.ilike(f'%{product_name}%'))
        if vendor:
            query = query.filter(Product.vendor.ilike(f'%{vendor}%'))

    rows = query.distinct().all()

    payload = []
    for row in rows:
        payload.append(
            {
                'cve_id': row.cve_id,
                'description': row.description,
                'cvss_score': float(row.cvss_score) if row.cvss_score is not None else None,
                'disclosure_date': row.disclosure_date.isoformat() if row.disclosure_date else None,
                'vuln_type': row.vuln_type,
                'source_url': row.source_url,
            }
        )

    return jsonify(payload)


@vulnerabilities_bp.get('/<string:cve_id>/related_patches')
def get_related_patches(cve_id: str):
    patches = Patch.query.filter_by(cve_id=cve_id.upper()).all()
    return jsonify(
        {
            'cve_id': cve_id.upper(),
            'patches': [
                {
                    'patch_id': p.patch_id,
                    'upgrade_path': p.upgrade_path,
                }
                for p in patches
            ],
        }
    )


@vulnerabilities_bp.post('/ingest')
def ingest_from_text():
    body = request.get_json(force=True)
    text = body.get('text', '')
    if not text.strip():
        return jsonify({'error': 'text is required'}), 400

    result = ingest_text_document(
        text,
        _normalize_hints(body.get('hints', {})),
        extractor_mode=body.get('extractor_mode'),
        source_url=body.get('source_url'),
    )
    return jsonify(result), 201


@vulnerabilities_bp.post('/ingest/url')
def ingest_from_url():
    body = request.get_json(force=True)
    url = str(body.get('url', '')).strip()
    if not url:
        return jsonify({'error': 'url is required'}), 400

    try:
        result = ingest_url_document(
            url=url,
            hints=_normalize_hints(body.get('hints', {})),
            extractor_mode=body.get('extractor_mode'),
        )
        return jsonify(result), 201
    except requests.RequestException as exc:
        return jsonify({'error': f'failed to fetch url: {exc}'}), 400


@vulnerabilities_bp.post('/ingest/file')
def ingest_from_file():
    uploaded_file = request.files.get('file')
    if uploaded_file is None or not uploaded_file.filename:
        return jsonify({'error': 'file is required'}), 400

    try:
        result = ingest_uploaded_file(
            filename=uploaded_file.filename,
            file_bytes=uploaded_file.read(),
            content_type=uploaded_file.content_type or '',
            hints=_normalize_hints(request.form),
            extractor_mode=request.form.get('extractor_mode'),
        )
        return jsonify(result), 201
    except Exception as exc:
        return jsonify({'error': f'failed to parse uploaded file: {exc}'}), 400


@vulnerabilities_bp.post('/crawl')
def crawl_from_url():
    body = request.get_json(force=True)
    start_url = str(body.get('url', '')).strip()
    if not start_url:
        return jsonify({'error': 'url is required'}), 400

    max_depth = _safe_positive_int(body.get('max_depth'), default=1, minimum=0, maximum=3)
    max_pages = _safe_positive_int(body.get('max_pages'), default=10, minimum=1, maximum=30)
    try:
        result = crawl_and_ingest(
            start_url=start_url,
            hints=_normalize_hints(body.get('hints', {})),
            extractor_mode=body.get('extractor_mode'),
            max_depth=max_depth,
            max_pages=max_pages,
        )
        return jsonify(result), 201
    except requests.RequestException as exc:
        return jsonify({'error': f'failed to crawl url: {exc}'}), 400


def _normalize_hints(values) -> dict[str, str]:
    keys = ('vendor', 'series', 'model', 'upgrade_path')
    normalized: dict[str, str] = {}
    for key in keys:
        raw = values.get(key) if hasattr(values, 'get') else None
        if raw is None:
            continue
        value = str(raw).strip()
        if value:
            normalized[key] = value
    return normalized


def _safe_positive_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))
