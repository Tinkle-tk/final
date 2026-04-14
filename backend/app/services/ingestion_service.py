from __future__ import annotations

from typing import Any

from flask import current_app

from ..extensions import db
from ..models import AffectedFirmware, FirmwareVersion, Patch, Product, Vulnerability, parse_date
from ..extractors.hybrid_extractor import extract_records
from ..extractors.nlp_extractor import ParsedRecord


def ingest_text_document(
    text: str,
    hints: dict[str, Any] | None = None,
    extractor_mode: str | None = None,
    source_url: str | None = None,
) -> dict[str, Any]:
    mode = extractor_mode or current_app.config.get('EXTRACTOR_MODE', 'hybrid')
    records, resolved_mode = extract_records(text=text, hints=hints, extractor_mode=mode)

    inserted = 0
    updated = 0

    for record in records:
        _, created = upsert_record(record, source_url=source_url)
        if created:
            inserted += 1
        else:
            updated += 1

    db.session.commit()
    return {
        'records': len(records),
        'inserted': inserted,
        'updated': updated,
        'extractor_mode': resolved_mode,
    }


def upsert_record(record: ParsedRecord, source_url: str | None = None) -> tuple[Vulnerability, bool]:
    vulnerability = Vulnerability.query.filter_by(cve_id=record.cve_id).first()
    created = False
    if vulnerability is None:
        vulnerability = Vulnerability(cve_id=record.cve_id, description=record.description)
        db.session.add(vulnerability)
        db.session.flush()
        created = True

    vulnerability.description = record.description
    vulnerability.cvss_score = record.cvss_score
    vulnerability.disclosure_date = parse_date(record.disclosure_date)
    vulnerability.vuln_type = record.vuln_type
    if source_url:
        vulnerability.source_url = source_url

    product = None
    if record.vendor and record.model:
        product = _get_or_create_product(record.vendor, record.series, record.model)

    if product and record.versions:
        for version_number in record.versions:
            firmware = _get_or_create_firmware(product.id, version_number)
            _link_vulnerability_firmware(vulnerability.id, firmware.id)

    for patch_id in record.patch_ids:
        exists = Patch.query.filter_by(cve_id=record.cve_id, patch_id=patch_id).first()
        if exists:
            continue
        db.session.add(Patch(cve_id=record.cve_id, patch_id=patch_id, upgrade_path=record.upgrade_path))

    return vulnerability, created


def _get_or_create_product(vendor: str, series: str | None, model: str) -> Product:
    query = Product.query.filter_by(vendor=vendor, series=series, model=model)
    product = query.first()
    if product:
        return product
    product = Product(vendor=vendor, series=series, model=model)
    db.session.add(product)
    db.session.flush()
    return product


def _get_or_create_firmware(product_id: int, version_number: str) -> FirmwareVersion:
    firmware = FirmwareVersion.query.filter_by(product_id=product_id, version_number=version_number).first()
    if firmware:
        return firmware
    firmware = FirmwareVersion(product_id=product_id, version_number=version_number)
    db.session.add(firmware)
    db.session.flush()
    return firmware


def _link_vulnerability_firmware(vulnerability_id: int, firmware_id: int) -> None:
    existing = AffectedFirmware.query.filter_by(
        vulnerability_id=vulnerability_id,
        firmware_version_id=firmware_id,
    ).first()
    if existing:
        return
    db.session.add(AffectedFirmware(vulnerability_id=vulnerability_id, firmware_version_id=firmware_id))
