"""
This module contains the Flask-Admin model views for the project.
Each class defines a view for a specific database model, with shared defaults and customizations for the admin interface.
"""

from flask_admin.contrib.sqla import ModelView

from admin_interface.admin_auth import can_access_admin, redirect_to_login

from configs.admin_interface_config import ADMIN_INTERFACE_PAGING_SIZE

class BaseAdminModelView(ModelView):
    """Shared Flask-Admin defaults for the project."""

    can_view_details = True
    can_export = True
    column_display_pk = True
    page_size = ADMIN_INTERFACE_PAGING_SIZE

    def is_accessible(self) -> bool:
        return can_access_admin()

    def inaccessible_callback(self, name, **kwargs):
        return redirect_to_login()


class ReadOnlyAdminModelView(BaseAdminModelView):
    """Admin view for tables that should start as read-only."""

    can_create = False
    can_edit = False
    can_delete = False


class UserAdminModelView(BaseAdminModelView):
    """Admin view for users, with sensitive fields hidden from forms and lists."""

    column_exclude_list = ("password",)
    form_excluded_columns = ("password",)
    column_searchable_list = ("email", "first_name", "last_name", "role")
    column_filters = ("role", "must_change_password")


class EntityAdminModelView(BaseAdminModelView):
    column_searchable_list = ("denomination", "manager_email")
    column_filters = ("manager_email",)


class HydrantAdminModelView(BaseAdminModelView):
    column_searchable_list = ("address", "status", "positioning", "surface_type")
    column_filters = ("status", "operational", "positioning", "surface_type")


class PhotoAdminModelView(BaseAdminModelView):
    column_searchable_list = ("path",)
    column_filters = ("hydrant_id",)


class MaintenanceAdminModelView(BaseAdminModelView):
    column_searchable_list = ("user_email", "notes", "type_")
    column_filters = ("outcome", "type_")