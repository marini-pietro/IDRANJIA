from api_blueprints import control_bp
from api_blueprints import blueprints_utils as bu

# This file contains unit tests for the Control Blueprint defined in control_bp.py


def test_control_resource_options():
    # Ensure that the class responds correctly to OPTIONS requests
    cls = control_bp.ControlResource
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    assert "Allow" in resp.headers
    assert "GET" in resp.headers["Allow"]


def test_control_post_resource_options():
    # Ensure that the class responds correctly to OPTIONS requests
    cls = control_bp.ControlPostResource
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    assert "POST" in resp.headers["Allow"] or "OPTIONS" in resp.headers["Allow"]
