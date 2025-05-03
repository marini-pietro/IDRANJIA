"""
This module contains the configuration settings for the API server, including:
- Authentication server settings
- Log server settings
- API server settings
- Database settings
- HTTP status codes and their explanations
- Authorization settings
"""

from typing import Dict
from datetime import timedelta

# Authentication server related settings
AUTH_SERVER_HOST: str = "localhost"  # The host of the authentication server
AUTH_SERVER_PORT: int = 6002  # The port of the authentication server
AUTH_SERVER_NAME_IN_LOG: str = "auth-server"
AUTH_SERVER_DEBUG_MODE: bool = True
AUTH_SERVER_SSL: bool = False  # Whether the authentication server uses SSL/TLS or not
AUTH_SERVER_SSL_CERT: str = (
    "/path/to/cert.pem"  # The path to the SSL/TLS certificate file
)
AUTH_SERVER_SSL_KEY: str = "/path/to/key.pem"  # The path to the SSL/TLS key file

# Log server related settings
LOG_SERVER_HOST: str = "localhost"  # The host of the log server
LOG_SERVER_PORT: int = (
    6014  # The port of the log server (default syslog port, can modified to open port for testing)
)
LOG_FILE_NAME: str = "pctowa_log.txt"
LOGGER_NAME: str = "pctowa_logger"  # The name of the logger
LOG_SERVER_NAME_IN_LOG: str = "log-server"  # The name of the server in the log messages
RATE_LIMIT_AMOUNT: int = 100  # Maximum messages per source
RATE_LIMIT_AMOUNT_TIME_WINDOW: int = 1  # Time window in seconds
DELAYED_LOGS_QUEUE_SIZE: int = 100  # The size of the delayed logs queue
# (if the queue is full, the oldest logs will
#  be removed to make space for new ones)
SYSLOG_SEVERITY_MAP: Dict[str, int] = {  # Define a severity map for the syslog server
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
API_SERVER_HOST: str = "localhost"
API_SERVER_PORT: int = 6000
API_SERVER_NAME_IN_LOG: str = "api-server"  # The name of the server in the log messages
API_VERSION: str = "v1"  # The version of the API
URL_PREFIX: str = f"/api/{API_VERSION}/"  # The prefix for all API endpoints
API_SERVER_DEBUG_MODE: bool = True  # Whether the API server is in debug mode or not
API_SERVER_SSL: bool = False  # Whether the API server uses SSL/TLS or not
API_SERVER_SSL_CERT: str = (
    "/path/to/cert.pem"  # The path to the SSL/TLS certificate file
)
API_SERVER_SSL_KEY: str = "/path/to/key.pem"  # The path to the SSL/TLS key file

# JWT custom configuration
JWT_SECRET_KEY: str = "Lorem ipsum dolor sit amet eget."
JWT_ALGORITHM: str = "HS256"  # The algorithm used to sign the JWT token
JWT_QUERY_STRING_NAME = "jwt_token"  # Custom name for the query string parameter
JWT_ACCESS_COOKIE_NAME = "jwt_access_cookie"  # Custom name for the access token cookie
JWT_REFRESH_COOKIE_NAME = (
    "jwt_refresh_cookie"  # Custom name for the refresh token cookie
)
JWT_JSON_KEY = "jwt_token"  # Custom key for the access token in JSON payloads
JWT_REFRESH_JSON_KEY = (
    "jwt_refresh_token"  # Custom key for the refresh token in JSON payloads
)
JWT_TOKEN_LOCATION = [
    "headers",
    "cookies",
    "query_string",
    "json",
]  # Where to look for the JWT token
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=10)  # Refresh token valid duration
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=3)  # Access token valid duration
# | Database configuration
DB_HOST: str = "localhost"
DB_NAME: str = "idranjia"
DB_USER: str = "root"
DB_PASSWORD: str = ""
CONNECTION_POOL_SIZE: int = 20  # The maximum number of connections in the pool


# Miscellaneous settings
# | HTTP status codes
STATUS_CODES: Dict[str, int] = {
    "not_found": 404,
    "unauthorized": 401,
    "forbidden": 403,
    "conflict": 409,
    "precondition_failed": 412,
    "unprocessable_entity": 422,
    "bad_request": 400,
    "created": 201,
    "ok": 200,
    "no_content": 204,
    "internal_error": 500,
    "service_unavailable": 503,
}
# | Roles and their corresponding IDs
ROLES: Dict[int, str] = {0: "admin", 1: "user"}

# | Standard not authorized message
NOT_AUTHORIZED_MESSAGE: Dict[str, str] = {
    "outcome": "error, action not permitted with current user"
}
