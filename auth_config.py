
"""
This module contains the configuration settings, including:
- Authentication server settings
- Log server settings
- API server settings
- Database settings
- HTTP status codes and their explanations
- Authorization settings

Configuration values are loaded from environment variables if set, otherwise default to hardcoded values (only suitable for development environments).
Some settings, because of their type complexity or reliance on other settings, cannot be set via environment variables and thus remain hardcoded in this file (none are sensitive).
Such settings should be modified directly in this file if needed, though in the vast majority of cases, this is unnecessary and not recommended.
To avoid boilerplate code, ensure consistency across the project, simplify maintenance/edits, all the other files in the project should import configuration values directly from this module.
Supports .env files via python-dotenv for easy overrides.
"""


from re import IGNORECASE as RE_IGNORECASE, compile as re_compile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Dict
from dotenv import load_dotenv
from datetime import timedelta
from os import environ as os_environ

if load_dotenv():  # Loads .env file if present
    print("Loaded environment variables from .env file.")
else: 
    print("No .env file found.")

# Authentication server related settings
AUTH_SERVER_HOST: str = os_environ.get("AUTH_SERVER_HOST", "localhost")
AUTH_SERVER_PORT: int = int(os_environ.get("AUTH_SERVER_PORT", 5001))
AUTH_API_VERSION: str = os_environ.get("AUTH_API_VERSION", "v1")
AUTH_SERVER_NAME_IN_LOG: str = os_environ.get("AUTH_SERVER_NAME_IN_LOG", "auth-server")
AUTH_SERVER_DEBUG_MODE: bool = os_environ.get("AUTH_SERVER_DEBUG_MODE", "True") == "True"
AUTH_SERVER_RATE_LIMIT: bool = os_environ.get("AUTH_SERVER_RATE_LIMIT", "True") == "True"
AUTH_SERVER_SSL_CERT: str = os_environ.get("AUTH_SERVER_SSL_CERT", "")
AUTH_SERVER_SSL_KEY: str = os_environ.get("AUTH_SERVER_SSL_KEY", "")
AUTH_SERVER_SSL: bool = not (
    AUTH_SERVER_SSL_CERT == "" and AUTH_SERVER_SSL_KEY == ""
)  # Whether the authentication server uses SSL/TLS or not

# PBKDF2 HMAC settings for password hashing
PBKDF2HMAC_SETTINGS: Dict[str, int] = {
    "algorithm": hashes.SHA256(),
    "length": 32,
    "iterations": 100000,
    "backend": default_backend(),
}

# JWT custom configuration (must match those in api_config.py)
JWT_SECRET_KEY: str = os_environ.get("JWT_SECRET_KEY", "Lorem ipsum dolor sit amet eget.")
JWT_ALGORITHM: str = os_environ.get("JWT_ALGORITHM", "HS256")
JWT_QUERY_STRING_NAME = os_environ.get("JWT_QUERY_STRING_NAME", "jwt_token")
JWT_JSON_KEY = os_environ.get("JWT_JSON_KEY", "jwt_token")
JWT_REFRESH_JSON_KEY = os_environ.get("JWT_REFRESH_JSON_KEY", "jwt_refresh_token")
JWT_TOKEN_LOCATION = os_environ.get("JWT_TOKEN_LOCATION", "headers,query_string,json").split(",")
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os_environ.get("JWT_REFRESH_TOKEN_EXPIRES_DAYS", 10)))
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os_environ.get("JWT_ACCESS_TOKEN_EXPIRES_HOURS", 3)))

# | Database configuration
DB_HOST = os_environ.get("DB_HOST", "localhost")
DB_NAME = os_environ.get("DB_NAME", "idranjia")
DB_USER = os_environ.get("DB_USER", "postgres")
DB_PASSWORD = os_environ.get("DB_PASSWORD", "postgres")
DB_PORT = os_environ.get("DB_PORT", "5432")

SQLALCHEMY_DATABASE_URI = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
SQLALCHEMY_TRACK_MODIFICATIONS = os_environ.get("SQLALCHEMY_TRACK_MODIFICATIONS", "False") == "True"


# Miscellaneous settings
# | Rate limiting settings TODO actually add rate limiting to auth server
RATE_LIMIT_MAX_REQUESTS: int = int(os_environ.get("RATE_LIMIT_MAX_REQUESTS", 50)) # max requests per time window
RATE_LIMIT_CACHE_SIZE: int = int(os_environ.get("RATE_LIMIT_CACHE_SIZE", 1000)) # number of unique clients to track
RATE_LIMIT_CACHE_TTL: int = int(os_environ.get("RATE_LIMIT_CACHE_TTL", 10)) # time window (in seconds) for rate limiting

# | HTTP status codes
STATUS_CODES: Dict[str, int] = {
    "not_found": 404,
    "unauthorized": 401,
    "forbidden": 403,
    "conflict": 409,
    "precondition_failed": 412,
    "unprocessable_entity": 422,
    "too_many_requests": 429,
    "gateway_timeout": 504,
    "bad_request": 400,
    "created": 201,
    "ok": 200,
    "no_content": 204,
    "internal_error": 500,
    "service_unavailable": 503,
}

# | Regex pattern for SQL injection detection
# This regex pattern is used to detect SQL injection attempts in user input.
# It matches common SQL keywords and commands that are often used in SQL injection attacks.
# Precompile the regex pattern once
SQL_PATTERN = re_compile(
    r"\b("
    + "|".join(
        [
            r"SELECT",
            r"INSERT",
            r"UPDATE",
            r"DELETE",
            r"DROP",
            r"CREATE",
            r"ALTER",
            r"EXEC",
            r"EXECUTE",
            r"SHOW",
            r"DESCRIBE",
            r"USE",
            r"LOAD",
            r"INTO",
            r"OUTFILE",
            r"INFORMATION_SCHEMA",
            r"DATABASES",
            r"SCHEMAS",
            r"COLUMNS",
            r"VALUES",
            r"UNION",
            r"ALL",
            r"WHERE",
            r"FROM",
            r"TABLE",
            r"JOIN",
            r"TRUNCATE",
            r"REPLACE",
            r"GRANT",
            r"REVOKE",
            r"DECLARE",
            r"CAST",
            r"SET",
            r"LIKE",
            r"OR",
            r"AND",
            r"HAVING",
            r"LIMIT",
            r"OFFSET",
            r"ORDER BY",
            r"GROUP BY",
            r"CONCAT",
            r"SLEEP",
            r"BENCHMARK",
            r"IF",
            r"ASCII",
            r"CHAR",
            r"HEX",
        ]
    )
    + r")\b"
    + r"|(--|#|;)",  # Match special characters without word boundaries
    RE_IGNORECASE,
)