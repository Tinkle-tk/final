from flask import Flask

from .config import Config
from .extensions import db
from .routes.products import products_bp
from .routes.vulnerabilities import vulnerabilities_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        from . import models  # noqa: F401

        db.create_all()

    @app.get('/health')
    def health() -> dict:
        return {'status': 'ok'}

    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(products_bp)

    return app
