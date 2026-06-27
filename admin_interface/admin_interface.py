"""
Starting point for the Flask-Admin interface.

This module creates a standalone Flask application, binds the shared SQLAlchemy
instance, and registers a first set of model views for the main database tables.
"""

# First party imports
from os import environ as os_environ

# Library imports
from flask import Flask
from flask_admin import Admin

# Local imports
from admin_interface.admin_auth import SecureAdminIndexView, register_admin_auth_routes
from configs.api_config import SQLALCHEMY_DATABASE_URI, SQLALCHEMY_TRACK_MODIFICATIONS
from models import Connector, Entity, Hydrant, Maintenance, Photo, User, UserEntity, db
from admin_interface.admin_interface_models import (
    EntityAdminModelView,
    HydrantAdminModelView,
    MaintenanceAdminModelView,
    PhotoAdminModelView,
    ReadOnlyAdminModelView,
    UserAdminModelView,
)
from configs.admin_interface_config import (
    ADMIN_INTERFACE_HOST,
    ADMIN_INTERFACE_PORT,
    ADMIN_INTERFACE_DEBUG,
)

def create_app() -> Flask:
    """Create the Flask application used to host the admin interface."""

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os_environ.get("ADMIN_INTERFACE_SECRET_KEY", "dev-admin-interface"),
        SQLALCHEMY_DATABASE_URI=SQLALCHEMY_DATABASE_URI,
        SQLALCHEMY_TRACK_MODIFICATIONS=SQLALCHEMY_TRACK_MODIFICATIONS,
        FLASK_ADMIN_SWATCH=os_environ.get("ADMIN_INTERFACE_SWATCH", "cerulean"),
    )

    db.init_app(app)
    register_admin_auth_routes(app)

    admin = Admin(
        app,
        name="IDRANTI SICURI Admin",
        url="/admin",
        index_view=SecureAdminIndexView(name="Home"),
    )

    admin.add_view(EntityAdminModelView(Entity, db.session, category="Core data"))
    admin.add_view(UserAdminModelView(User, db.session, category="Identity"))
    admin.add_view(ReadOnlyAdminModelView(UserEntity, db.session, category="Identity"))
    admin.add_view(HydrantAdminModelView(Hydrant, db.session, category="Hydrants"))
    admin.add_view(ReadOnlyAdminModelView(Connector, db.session, category="Hydrants"))
    admin.add_view(PhotoAdminModelView(Photo, db.session, category="Media"))
    admin.add_view(
        MaintenanceAdminModelView(Maintenance, db.session, category="Maintenance")
    )

    return app


# Create the Flask application for the admin interface
admin_app = create_app()

if __name__ == "__main__":
    admin_app.run(
        host=ADMIN_INTERFACE_HOST, 
        port=ADMIN_INTERFACE_PORT, 
        debug=ADMIN_INTERFACE_DEBUG)
