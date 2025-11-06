from api_blueprints import operator_bp
from api_blueprints import blueprints_utils as bu

# This file contains unit tests for the Operator Blueprint defined in operator_bp.py


def test_operator_resource_options_and_validation():
    cls = operator_bp.OperatorResource
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    assert "GET" in resp.headers["Allow"]


def test_operator_post_options():
    cls = operator_bp.OperatorPostResource
    resp = bu.handle_options_request(cls)
    assert resp.status_code == 200
    assert "POST" in resp.headers["Allow"]
