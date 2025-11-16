import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import auth_server

# This file contains unit tests for the functions and features defined in auth_server.py


def make_stored_password(plain_password: str) -> str:
    salt = os.urandom(16)  # Generate a random 16-byte salt
    salt_b64 = base64.urlsafe_b64encode(
        salt
    ).decode()  # Encode salt to base64 for storage
    kdf = PBKDF2HMAC(  # Use PBKDF2HMAC for key derivation
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    hash_bytes = kdf.derive(plain_password.encode("utf-8"))  # Derive the hash
    hash_b64 = base64.urlsafe_b64encode(
        hash_bytes
    ).decode()  # Encode hash to base64 for storage
    return f"{salt_b64}:{hash_b64}"  # Store as "salt:hash"


def test_verify_password_success_and_failure():
    pwd = "mysecret"  # Arbitrary test password
    stored = make_stored_password(pwd)  # Create stored password format
    assert auth_server.verify_password(stored, pwd) is True  # Correct password
    assert auth_server.verify_password(stored, "wrong") is False  # Incorrect password


def test_is_input_safe_auth():
    assert auth_server.is_input_safe("hello") is True  # Simple safe string
    assert auth_server.is_input_safe(["a", "b"]) is True  # List of safe strings
    assert auth_server.is_input_safe({"k": "v"}) is True  # Dictionary of safe strings
    assert auth_server.is_input_safe("DROP TABLE users") is False  # Unsafe string


def test_health_check():
    # Use Flask test client to call the health check endpoint
    client = auth_server.auth_api.test_client()
    r = client.get("/health")  # Call health check endpoint
    assert r.status_code == auth_server.STATUS_CODES["ok"]  # Check for 200 status code
    assert r.get_json() == {"status": "ok"}  # Check response content
