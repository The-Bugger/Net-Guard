"""
backend/api/__init__.py — Flask application factory for NetGuard IDPS.

Creates the Flask app, registers all route blueprints, configures CORS,
and initialises Flask-SocketIO with the eventlet worker.

Eventlet monkey-patching is applied in main.py BEFORE this module is imported.

Requirements: 13.1, 13.2
"""

from __future__ import annotations

import logging

import os

from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

logger = logging.getLogger("netguard.app")

# SocketIO instance — shared across the application
socketio = SocketIO()


def create_app(config: dict | None = None) -> Flask:
    """
    Flask application factory.

    Args:
        config: Optional dict of Flask config overrides.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(
        __name__,
        static_folder="../../frontend",
        template_folder="../../frontend",
    )

    # Default configuration
    app.config["SECRET_KEY"] = "netguard-dev-secret-change-in-production"
    app.config["JSON_SORT_KEYS"] = False

    if config:
        app.config.update(config)

    # Enable CORS — restrict to ALLOWED_ORIGINS in production; default "*" for dev
    _origins = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
    CORS(app, resources={r"/api/*": {"origins": _origins}})

    # Initialise SocketIO — use threading mode in tests (eventlet incompatible with Python 3.14)
    async_mode = app.config.get("SOCKETIO_ASYNC_MODE") or os.environ.get("SOCKETIO_ASYNC_MODE", "eventlet")
    socketio.init_app(
        app,
        async_mode=async_mode,
        cors_allowed_origins=_origins,
        logger=False,
        engineio_logger=False,
    )

    # Register rate limiter (before_request)
    from backend.middleware.rate_limiter import RateLimiter
    limiter = RateLimiter()
    app.before_request(limiter.check)

    # Register security headers + input sanitisation middleware (Req 11.1, 11.2, 11.3)
    from backend.middleware.security_headers import add_security_headers, sanitise_and_validate
    app.after_request(add_security_headers)
    app.before_request(sanitise_and_validate)

    # Global error handler — log traceback, return clean JSON, never expose it (Req 11.4)
    from flask import jsonify, request, send_from_directory

    _frontend = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")

    def _is_api(req) -> bool:
        return req.path.startswith("/api/")

    @app.errorhandler(404)
    def handle_404(exc):
        if _is_api(request):
            return jsonify({"success": False, "error": "NOT_FOUND", "message": "Resource not found."}), 404
        return send_from_directory(_frontend, "404.html"), 404

    @app.errorhandler(500)
    def handle_500(exc):
        logger.error("500 error", exc_info=True)
        if _is_api(request):
            return jsonify({"success": False, "error": "INTERNAL_ERROR", "message": "An internal error occurred."}), 500
        return send_from_directory(_frontend, "500.html"), 500

    @app.errorhandler(Exception)
    def handle_unhandled(exc: Exception):
        logger.error("Unhandled exception", exc_info=True)
        if _is_api(request):
            return jsonify({"success": False, "error": "INTERNAL_ERROR", "message": "An internal error occurred."}), 500
        return send_from_directory(_frontend, "500.html"), 500

    # Register all route blueprints
    _register_blueprints(app)

    # Serve dashboard at root
    _register_frontend_routes(app)

    logger.info("Flask application created.")
    return app


def _register_blueprints(app: Flask) -> None:
    """Register all API route blueprints under /api/v1."""
    from backend.routes.health_routes import health_bp
    from backend.routes.monitor_routes import monitor_bp
    from backend.routes.detection_routes import detection_bp
    from backend.routes.block_routes import block_bp
    from backend.routes.whitelist_routes import whitelist_bp
    from backend.routes.dashboard_routes import dashboard_bp
    from backend.routes.stats_routes import stats_bp
    from backend.routes.evidence_routes import evidence_bp
    from backend.routes.logs_routes import logs_bp
    from backend.routes.settings_routes import settings_bp
    from backend.routes.timeline_routes import timeline_bp
    from backend.routes.analytics_routes import analytics_bp
    from backend.routes.export_routes import export_bp
    from backend.routes.ai_assistant_routes import ai_assistant_bp
    from backend.routes.lan_devices_routes import lan_devices_bp
    from backend.routes.advisor_routes import advisor_bp
    from backend.routes.reset_routes import reset_bp

    prefix = "/api/v1"
    app.register_blueprint(health_bp, url_prefix=prefix)
    app.register_blueprint(monitor_bp, url_prefix=prefix)
    app.register_blueprint(detection_bp, url_prefix=prefix)
    app.register_blueprint(block_bp, url_prefix=prefix)
    app.register_blueprint(whitelist_bp, url_prefix=prefix)
    app.register_blueprint(dashboard_bp, url_prefix=prefix)
    app.register_blueprint(stats_bp, url_prefix=prefix)
    app.register_blueprint(evidence_bp, url_prefix=prefix)
    app.register_blueprint(logs_bp, url_prefix=prefix)
    app.register_blueprint(settings_bp, url_prefix=prefix)
    app.register_blueprint(timeline_bp, url_prefix=prefix)
    app.register_blueprint(analytics_bp, url_prefix=prefix)
    app.register_blueprint(export_bp, url_prefix=prefix)
    app.register_blueprint(ai_assistant_bp, url_prefix=prefix)
    app.register_blueprint(lan_devices_bp, url_prefix=prefix)
    app.register_blueprint(advisor_bp, url_prefix=prefix)
    app.register_blueprint(reset_bp, url_prefix=prefix)

    logger.info("All route blueprints registered under %s.", prefix)


def _register_frontend_routes(app: Flask) -> None:
    """Serve the frontend HTML pages."""
    from flask import render_template, send_from_directory
    import os

    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")

    @app.route("/")
    def index():
        return send_from_directory(frontend_dir, "index.html")

    @app.route("/timeline")
    def timeline_page():
        return send_from_directory(frontend_dir, "timeline.html")

    @app.route("/analytics")
    def analytics_page():
        return send_from_directory(frontend_dir, "analytics.html")

    @app.route("/about")
    def about_page():
        return send_from_directory(frontend_dir, "about.html")

    @app.route("/architecture")
    def architecture_page():
        return send_from_directory(frontend_dir, "architecture.html")

    @app.route("/landing")
    def landing_page():
        return send_from_directory(frontend_dir, "landing.html")

    @app.route("/<path:filename>")
    def frontend_static(filename):
        return send_from_directory(frontend_dir, filename)
