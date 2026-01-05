from re import IGNORECASE as RE_IGNORECASE, compile as re_compile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Dict, Set, Tuple
from dotenv import load_dotenv
from datetime import timedelta
from os import environ as os_environ

if load_dotenv():  # Loads .env file if present
    print("Loaded environment variables from .env file in api_config.py")
else: 
    print("No .env file found.")

# Authentication server related settings
AUTH_SERVER_HOST: str = os_environ.get("AUTH_SERVER_HOST", "localhost")
AUTH_SERVER_PORT: int = int(os_environ.get("AUTH_SERVER_PORT", 5001))
IS_AUTH_SERVER_SSL: bool = os_environ.get("IS_AUTH_SERVER_SSL", "False") == "True"
JWT_VALIDATION_CACHE_SIZE: int = int(os_environ.get("JWT_VALIDATION_CACHE_SIZE", 1000))
JWT_VALIDATION_CACHE_TTL: int = int(os_environ.get("JWT_VALIDATION_CACHE_TTL", 3600))
# PBKDF2 HMAC settings for password hashing (have to match those in auth_config.py)
PBKDF2HMAC_SETTINGS: Dict[str, int] = {
    "algorithm": hashes.SHA256(),
    "length": 32,
    "iterations": 100000,
    "backend": default_backend(),
}

# Log server related settings
LOG_SERVER_HOST: str = os_environ.get("LOG_SERVER_HOST", "localhost") # host on which the log server listens for incoming syslog messages
LOG_SERVER_PORT: int = int(os_environ.get("LOG_SERVER_PORT", 5002)) # port on which the log server listens for incoming syslog messages
SYSLOG_SEVERITY_MAP: Dict[str, int] = {  # Define a severity map for the syslog server (should not change as it follows syslog standard)
    "emergency": 0,  # System is unusable
    "alert": 1,  # Action must be taken immediately
    "critical": 2,  # Critical conditions
    "error": 3,  # Error conditions
    "warning": 4,  # Warning conditions
    "notice": 5,  # Normal but significant condition
    "info": 6,  # Informational messages
    "debug": 7,  # Debug-level messages
}

# API server related settings
# | API server settings
API_SERVER_HOST: str = os_environ.get("API_SERVER_HOST", "localhost")
API_SERVER_PORT: int = int(os_environ.get("API_SERVER_PORT", 5000))
API_SERVER_NAME_IN_LOG: str = os_environ.get("API_SERVER_NAME_IN_LOG", "api-server")
API_VERSION: str = os_environ.get("API_VERSION", "v1")
URL_PREFIX: str = f"/api/{API_VERSION}"
API_SERVER_DEBUG_MODE: bool = os_environ.get("API_SERVER_DEBUG_MODE", "True") == "True"
API_SERVER_RATE_LIMIT: bool = os_environ.get("API_SERVER_RATE_LIMIT", "True") == "True"
API_SERVER_MAX_JSON_SIZE = int(os_environ.get("API_SERVER_MAX_JSON_SIZE", 50 * 10244))
SQL_SCAN_MAX_LEN = int(os_environ.get("SQL_SCAN_MAX_LEN", 2048))
SQL_SCAN_MAX_RECURSION_DEPTH = int(os_environ.get("SQL_SCAN_MAX_RECURSION_DEPTH", 10))
LOGIN_AVAILABLE_THROUGH_API: bool = AUTH_SERVER_HOST in {
    "localhost",
    "127.0.0.1",
}
API_SERVER_SSL_CERT: str = os_environ.get("API_SERVER_SSL_CERT", "")
API_SERVER_SSL_KEY: str = os_environ.get("API_SERVER_SSL_KEY", "")
API_SERVER_SSL: bool = not (
    API_SERVER_SSL_CERT == "" and API_SERVER_SSL_KEY == ""
)

# JWT custom configuration
JWT_SECRET_KEY: str = os_environ.get("JWT_SECRET_KEY", "Lorem ipsum dolor sit amet eget.")
JWT_ALGORITHM: str = os_environ.get("JWT_ALGORITHM", "HS256")
JWT_QUERY_STRING_NAME = os_environ.get("JWT_QUERY_STRING_NAME", "jwt_token") # name of the query string parameter to look for JWTs (if JWTs are sent via query string, not recommended for production)
JWT_JSON_KEY = os_environ.get("JWT_JSON_KEY", "jwt_token") # name of the JSON key to look for JWTs (if JWTs are sent via JSON body)
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
# | Rate limiting settings
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

# | Roles and their corresponding IDs
ROLES: Set[str] = {"admin", "operator", "viewer"}

# | Standard not authorized message
NOT_AUTHORIZED_MESSAGE: Dict[str, str] = {
    "outcome": "error, action not permitted with current user"
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

# Flasgger (Swagger UI) configuration
SWAGGER_CONFIG = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs/",
}

# Invalid JWT token related messages
# Store plain payload dicts and status codes here; call jsonify() inside request handlers.
INVALID_JWT_MESSAGES: Dict[str, Tuple[Dict[str, str], int]] = {
    "missing_token": ({"error": "missing token"}, STATUS_CODES["unauthorized"]),
    "invalid_token": (
        {"error": "provided token is invalid"},
        STATUS_CODES["unprocessable_entity"],
    ),
    "expired_token": (
        {"error": "provided token is expired"},
        STATUS_CODES["unauthorized"],
    ),
    "revoked_token": (
        {"error": "provided token has been revoked"},
        STATUS_CODES["unauthorized"],
    ),
}
