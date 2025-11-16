from api_blueprints import hydrant_bp
from api_blueprints import blueprints_utils as bu

# This file contains unit tests for the Hydrant Blueprint defined in hydrant_bp.py


def test_hydrant_resource_endpoints_and_options():
    # Ensure class defines endpoint paths
    cls = hydrant_bp.HydrantResource
    assert hasattr(cls, "ENDPOINT_PATHS")

    # Use handle_options_request on the class
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    assert "Allow" in resp.headers
    # Should at least include GET and OPTIONS
    assert "GET" in resp.headers["Allow"]
    assert "OPTIONS" in resp.headers["Allow"]


def test_hydrant_post_resource_options():
    cls = hydrant_bp.HydrantPostResource
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    # Ensure POST is allowed for the POST resource's OPTIONS response
    assert "POST" in resp.headers["Allow"]
