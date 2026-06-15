"""Admin module for WAF prototype.

Provides a Flask Blueprint `admin_bp` implemented in `routes.py`.
"""

from .routes import admin_bp

__all__ = ["admin_bp"]
