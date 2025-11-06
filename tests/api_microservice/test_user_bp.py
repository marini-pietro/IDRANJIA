import json
from api_blueprints import user_bp
from api_blueprints import blueprints_utils as bu
from api_server import main_api
import types

# This file contains unit tests for the User Blueprint defined in user_bp.py


def test_hash_password_format():
    hp = user_bp.hash_password("secret123")
    assert isinstance(hp, str)
    assert ":" in hp
    salt, hashed = hp.split(":", 1)
    assert salt != "" and hashed != ""


def test_user_login_forwards_request(monkeypatch):
    # Simulate auth service returning OK
    class DummyResp:
        status_code = 200

        def json(self):
            return {"access_token": "tok", "refresh_token": "rtok"}

    def fake_post(url, json=None, timeout=None):
        return DummyResp()

    monkeypatch.setattr(user_bp, "requests_post", fake_post)

    # Use the app's request context to provide JSON body
    with main_api.test_request_context(json={"email": "u@x.com", "password": "p"}):
        resp = user_bp.UserLogin().post()
        # It's a flask Response
        assert resp.status_code == bu.STATUS_CODES["ok"]
        assert resp.get_json()["access_token"] == "tok"


def test_user_login_handles_unauthorized(monkeypatch):
    class DummyResp:
        status_code = bu.STATUS_CODES["unauthorized"]

        def json(self):
            return {}

    def fake_post(url, json=None, timeout=None):
        return DummyResp()

    monkeypatch.setattr(user_bp, "requests_post", fake_post)

    with main_api.test_request_context(json={"email": "u@x.com", "password": "p"}):
        resp = user_bp.UserLogin().post()
        assert resp.status_code == bu.STATUS_CODES["unauthorized"]
