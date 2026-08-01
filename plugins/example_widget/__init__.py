"""
example_widget — Example NetGuard plugin.

Demonstrates the plugin interface. Adds a read-only /api/v1/plugins/example/widget
endpoint that returns a static info payload.

Requirements: 13.6
"""

from flask import Blueprint

PLUGIN_META = {
    "name": "Example Widget",
    "version": "1.0.0",
    "description": "A demo plugin that adds a /api/v1/plugins/example/widget endpoint.",
}

_bp = Blueprint("example_widget", __name__)


@_bp.get("/plugins/example/widget")
def widget():
    from backend.utils.response import success_response
    return success_response({
        "plugin": PLUGIN_META["name"],
        "version": PLUGIN_META["version"],
        "message": "Example plugin is active.",
    })


def register(app) -> None:
    """Called by PluginRegistry.load() when the plugin is activated."""
    app.register_blueprint(_bp, url_prefix="/api/v1")
