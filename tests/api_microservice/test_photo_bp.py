from api_blueprints import photo_bp
from api_blueprints import blueprints_utils as bu

# This file contains unit tests for the Photo Blueprint defined in photo_bp.py


def test_photo_resource_options():
    cls = photo_bp.PhotoResource
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    assert "GET" in resp.headers["Allow"]


def test_photo_post_options():
    cls = photo_bp.PhotoPostResource
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    assert "POST" in resp.headers["Allow"]
