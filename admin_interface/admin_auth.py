"""Authentication helpers for the Flask-Admin interface.

The microservices architecture in this repository keeps its main login flow based on
JWT tokens issued by ``auth_server.py`` and validated by the API layer. The admin
interface uses a separate Flask session so it can protect the UI without changing
that existing JWT-based service-to-service design.
"""

# First party imports
from base64 import urlsafe_b64decode
from binascii import Error as BinasciiError

# Library imports
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import redirect, render_template_string, request, session, url_for
from flask_admin import AdminIndexView

# Local imports
from configs.api_config import PBKDF2HMAC_SETTINGS
from models import User, db

# Hard-coded credentials for development and testing purposes to avoid wasting time creating an user
# (password are hashed with PBKDF2HMAC, so users cannot be created by simply inserting a row into the database, they must be created through the API or the admin interface)
DEV_ADMIN_EMAIL = "admin@idrantisicuri.local"
DEV_ADMIN_PASSWORD = "devadmin123"

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IDRANTI SICURI Admin Login</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f4f7fb; color: #1f2937; }
      .card { width: min(92vw, 420px); background: white; border-radius: 14px; padding: 28px; box-shadow: 0 18px 50px rgba(15, 23, 42, 0.12); }
      h1 { margin-top: 0; font-size: 1.5rem; }
      label { display: block; margin: 14px 0 6px; font-weight: 600; }
      input { width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 10px; font-size: 1rem; }
      button { width: 100%; margin-top: 18px; padding: 11px 14px; border: 0; border-radius: 10px; background: #0f766e; color: white; font-size: 1rem; font-weight: 700; cursor: pointer; }
      .error { margin: 0 0 12px; color: #b91c1c; font-weight: 600; }
      .hint { margin-top: 14px; font-size: 0.9rem; color: #475569; line-height: 1.4; }
      .dev { margin-top: 14px; font-size: 0.82rem; color: #64748b; }
    </style>
  </head>
  <body>
    <form class="card" method="post">
      <h1>IDRANTI SICURI Admin</h1>
      {% if error %}<p class="error">{{ error }}</p>{% endif %}
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign in</button>
      <p class="hint">Access is restricted to administrator accounts. A development fallback account is also available for local work.</p>
      <p class="dev">Development override: {{ dev_email }}</p>
    </form>
  </body>
</html>
"""


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a stored PBKDF2 password hash."""

    try:
        salt_b64, hash_b64 = stored_password.split(":")
    except ValueError:
        return False

    try:
        salt = urlsafe_b64decode(salt_b64)
        hash_bytes = urlsafe_b64decode(hash_b64)
    except (BinasciiError, ValueError):
        return False

    try:
        kdf = PBKDF2HMAC(
            algorithm=PBKDF2HMAC_SETTINGS["algorithm"],
            length=PBKDF2HMAC_SETTINGS["length"],
            salt=salt,
            iterations=PBKDF2HMAC_SETTINGS["iterations"],
        )
        kdf.verify(provided_password.encode("utf-8"), hash_bytes)
        return True
    except InvalidKey:
        return False


def authenticate_admin(email: str, password: str):
    """Return an authenticated admin identity if credentials are valid."""

    if email == DEV_ADMIN_EMAIL and password == DEV_ADMIN_PASSWORD:
        return {"email": DEV_ADMIN_EMAIL, "role": "amministratore", "is_dev_account": True}

    user = db.session.query(User).filter_by(email=email).one_or_none()
    if user is None or user.role != "amministratore":
        return None
    if not verify_password(user.password, password):
        return None

    return {"email": user.email, "role": user.role, "is_dev_account": False}


def is_authenticated_admin() -> bool:
    """Return True when the current session is allowed to use the admin UI."""

    return bool(session.get("admin_authenticated") and session.get("admin_role") == "amministratore")


def can_access_admin() -> bool:
    """Return True when the current session is allowed to use the admin UI."""

    return is_authenticated_admin()


def redirect_to_login():
    """Redirect unauthorized users to the admin login form."""

    return redirect(url_for("admin_login", next=request.url))


class SecureAdminIndexView(AdminIndexView):
    """Admin dashboard view protected by the admin authentication gate."""

    def is_accessible(self) -> bool:
        return can_access_admin()

    def inaccessible_callback(self, name, **kwargs):
        return redirect_to_login()


def register_admin_auth_routes(app) -> None:
    """Register login and logout routes for the admin interface."""

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if is_authenticated_admin():
            return redirect(url_for("admin.index"))

        error = None
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            admin_identity = authenticate_admin(email, password)
            if admin_identity is not None:
                session["admin_authenticated"] = True
                session["admin_email"] = admin_identity["email"]
                session["admin_role"] = admin_identity["role"]
                session["admin_is_dev_account"] = admin_identity["is_dev_account"]
                return redirect(request.args.get("next") or url_for("admin.index"))
            error = "Invalid credentials or insufficient permissions."

        return render_template_string(
            LOGIN_TEMPLATE,
            error=error,
            dev_email=DEV_ADMIN_EMAIL,
        )

    @app.route("/admin/logout")
    def admin_logout():
        session.pop("admin_authenticated", None)
        session.pop("admin_email", None)
        session.pop("admin_role", None)
        session.pop("admin_is_dev_account", None)
        return redirect(url_for("admin_login"))