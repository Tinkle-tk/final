from datetime import date, datetime

from .extensions import db


class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vendor = db.Column(db.String(100), nullable=False, index=True)
    series = db.Column(db.String(100), nullable=True)
    model = db.Column(db.String(100), nullable=False, index=True)

    firmware_versions = db.relationship('FirmwareVersion', back_populates='product', cascade='all, delete-orphan')

    __table_args__ = (
        db.UniqueConstraint('vendor', 'series', 'model', name='uq_product_identity'),
    )


class FirmwareVersion(db.Model):
    __tablename__ = 'firmware_versions'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id', ondelete='CASCADE'), nullable=False, index=True)
    version_number = db.Column(db.String(50), nullable=False, index=True)
    release_date = db.Column(db.Date, nullable=True)

    product = db.relationship('Product', back_populates='firmware_versions')
    affected_vulnerabilities = db.relationship(
        'AffectedFirmware',
        back_populates='firmware_version',
        cascade='all, delete-orphan',
    )

    __table_args__ = (
        db.UniqueConstraint('product_id', 'version_number', name='uq_product_version'),
    )


class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cve_id = db.Column(db.String(50), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=False)
    cvss_score = db.Column(db.Numeric(3, 1), nullable=True)
    disclosure_date = db.Column(db.Date, nullable=True)
    vuln_type = db.Column(db.String(100), nullable=True)
    source_url = db.Column(db.String(500), nullable=True)

    patches = db.relationship('Patch', back_populates='vulnerability', cascade='all, delete-orphan')
    affected_firmware = db.relationship('AffectedFirmware', back_populates='vulnerability', cascade='all, delete-orphan')


class Patch(db.Model):
    __tablename__ = 'patches'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cve_id = db.Column(
        db.String(50),
        db.ForeignKey('vulnerabilities.cve_id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    patch_id = db.Column(db.String(50), nullable=False)
    upgrade_path = db.Column(db.Text, nullable=True)

    vulnerability = db.relationship('Vulnerability', back_populates='patches')

    __table_args__ = (
        db.UniqueConstraint('cve_id', 'patch_id', name='uq_patch_identity'),
    )


class AffectedFirmware(db.Model):
    __tablename__ = 'affected_firmware'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vulnerability_id = db.Column(
        db.Integer,
        db.ForeignKey('vulnerabilities.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    firmware_version_id = db.Column(
        db.Integer,
        db.ForeignKey('firmware_versions.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )

    vulnerability = db.relationship('Vulnerability', back_populates='affected_firmware')
    firmware_version = db.relationship('FirmwareVersion', back_populates='affected_vulnerabilities')

    __table_args__ = (
        db.UniqueConstraint('vulnerability_id', 'firmware_version_id', name='uq_affect_relation'),
    )


def parse_date(value: str | None) -> date | None:
    if not value:
        return None
    for fmt in ('%Y-%m-%d', '%Y/%m/%d'):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            pass
    return None
