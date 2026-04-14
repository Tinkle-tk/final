from flask import Blueprint, jsonify

from ..models import Product

products_bp = Blueprint('products', __name__, url_prefix='/products')


@products_bp.get('/<int:product_id>/affected_vulnerabilities')
def get_affected_vulnerabilities(product_id: int):
    product = Product.query.get_or_404(product_id)

    vulnerabilities_payload = []
    for fw in product.firmware_versions:
        for link in fw.affected_vulnerabilities:
            vulnerability = link.vulnerability
            vulnerabilities_payload.append(
                {
                    'cve_id': vulnerability.cve_id,
                    'description': vulnerability.description,
                    'cvss_score': float(vulnerability.cvss_score) if vulnerability.cvss_score is not None else None,
                    'disclosure_date': (
                        vulnerability.disclosure_date.isoformat() if vulnerability.disclosure_date else None
                    ),
                    'firmware_version': fw.version_number,
                }
            )

    dedup = {item['cve_id'] + '|' + item['firmware_version']: item for item in vulnerabilities_payload}

    return jsonify(
        {
            'product': {
                'id': product.id,
                'vendor': product.vendor,
                'series': product.series,
                'model': product.model,
            },
            'affected_vulnerabilities': list(dedup.values()),
        }
    )
