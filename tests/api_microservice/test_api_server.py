import pytest
from api_server import is_input_safe, main_api, API_VERSION, STATUS_CODES

# This file contains unit tests for the functions and features defined in api_server.py


def test_is_input_safe_string():
    # Checks that a normal string is considered safe
    assert is_input_safe("hello world") is True


def test_is_input_safe_sql_injection():
    # Checks that a SQL injection string is considered unsafe
    assert is_input_safe("SELECT * FROM users WHERE id=1") is False


def test_is_input_safe_list_and_dict():
    # Checks that lists and dicts are considered safe or unsafe appropriately
    assert is_input_safe(["one", "two"]) is True
    assert is_input_safe({"key": "value"}) is True
    assert is_input_safe({"drop": "DROP TABLE"}) is False


def test_health_check_endpoint():
    # Uses the test client to call the health endpoint to verify response
    client = main_api.test_client()
    resp = client.get(f"/api/{API_VERSION}/health")
    assert resp.status_code == STATUS_CODES["ok"]
    assert resp.get_json() == {"status": "ok"}
