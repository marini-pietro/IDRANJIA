"""
Utility functions for the API blueprints.
These functions include data validation, authorization checks, response creation,
database connection handling, logging, and token validation.
"""

import socket
from datetime import datetime, timezone
from functools import wraps
from inspect import isclass as inspect_isclass, signature as inspect_signature
from os import getpid
from queue import Queue
from sys import exit as sys_exit
from threading import Lock, Thread
from typing import Any, Dict, List, Tuple, Union

from contextlib import contextmanager
from cachetools import TTLCache
from flask import Response, jsonify, make_response, request
from mysql.connector.pooling import MySQLConnectionPool
from requests import post as requests_post
from requests.exceptions import Timeout
from requests.exceptions import RequestException

from config import (
    API_SERVER_HOST,
    API_SERVER_NAME_IN_LOG,
    API_SERVER_PORT,
    API_SERVER_SSL,
    AUTH_SERVER_HOST,
    AUTH_SERVER_PORT,
    AUTH_SERVER_SSL,
    CONNECTION_POOL_SIZE,
    DB_HOST,
    DB_NAME,
    DB_PASSWORD,
    DB_USER,
    JWT_JSON_KEY,
    JWT_QUERY_STRING_NAME,
    JWT_VALIDATION_CACHE_SIZE,
    JWT_VALIDATION_CACHE_TTL,
    LOG_SERVER_HOST,
    LOG_SERVER_PORT,
    NOT_AUTHORIZED_MESSAGE,
    RATE_LIMIT_CACHE_SIZE,
    RATE_LIMIT_CACHE_TTL,
    RATE_LIMIT_MAX_REQUESTS,
    ROLES,
    STATUS_CODES,
    SYSLOG_SEVERITY_MAP,
    URL_PREFIX,
)

# Authentication related
# Cache for token validation results
token_validation_cache = TTLCache(
    maxsize=JWT_VALIDATION_CACHE_SIZE, ttl=JWT_VALIDATION_CACHE_TTL
)


def jwt_validation_required(func):
    """
    Decorator to validate the JWT token before executing the endpoint function.

    If the token is invalid, it returns a 401 Unauthorized response.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Extract the token from the Authorization header
        auth_header = request.headers.get("Authorization", None)
        token = auth_header.replace("Bearer ", "")

        # If the token is not in the Authorization header, check the query string
        if token is None:
            token = request.args.get(JWT_QUERY_STRING_NAME, "")

        # If the token is not in the query string, check the JSON body
        if token is None:
            json_body = request.get_json(silent=True)  # Safely get JSON body
            if json_body:  # Ensure it's not None
                token = json_body.get(JWT_JSON_KEY, None)

        # Validate the token
        if token is None:
            return {"error": "missing token"}, STATUS_CODES["unauthorized"]

        # Initialize identity and role
        identity = None
        role = None

        # Check if the token is already validated in the cache
        if token in token_validation_cache:
            identity, role = token_validation_cache[token]
        else:
            # Contact the authentication microservice to validate the token
            try:
                # Send a request to the authentication server to validate the token
                # Proper json body and headers are not needed
                response: Response = requests_post(
                    f"{"https" if AUTH_SERVER_SSL else "http"}://{AUTH_SERVER_HOST}:{AUTH_SERVER_PORT}/auth/validate",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5, # in seconds
                )



                # If the token is invalid, return a 401 Unauthorized response
                if response.status_code != STATUS_CODES["ok"]:
                    return {"error": "Invalid token"}, STATUS_CODES["unauthorized"]
                else:
                # Extract the identity from the response JSON if valid
                    response_json = response.json()
                    identity = response_json.get("identity")
                    role = response_json.get("role")

                # Cache the result if the token is valid
                token_validation_cache[token] = identity, role

            except Timeout:
                log(
                    log_type="error",
                    message="Request timed out while validating token",
                    origin_name="JWTValidation",
                    origin_host=API_SERVER_HOST,
                )
                return {"error": "Login request timed out"}, STATUS_CODES["gateway_timeout"]

            except RequestException as ex:
                log(
                    log_type="error",
                    message=f"Error validating token: {ex}",
                    origin_name="JWTValidation",
                    origin_host=API_SERVER_HOST,
                )
                return {"error": "internal server error while validating token"}, STATUS_CODES["internal_error"]

        # Pass the extracted identity to the wrapped function
        # Only if the function accepts it (OPTIONS endpoint do not use it)
        if "identity" in inspect_signature(func).parameters:
            kwargs["identity"] = identity

        kwargs["role"] = role  # Add role to kwargs for the next wrapper
        return func(*args, **kwargs)

    return wrapper


# Authorization related
def check_authorization(allowed_roles: List[str]):
    """
    Decorator to check if the user's role is in the allowed list.

    params:
        allowed_roles: List[str] - List of user roles that are permitted to execute the function.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract the role from kwargs (passed by jwt_validation_required)
            user_role = kwargs.pop("role", None)  # Remove 'role' after retrieving it

            # Check if the user role is present
            if user_role is None:
                return create_response(
                    message={"error": "user role not present in token"},
                    status_code=STATUS_CODES["bad_request"],
                )

            # Check if the user role is valid
            if user_role not in ROLES:
                return create_response(
                    message={"error": "invalid user role"},
                    status_code=STATUS_CODES["bad_request"],
                )

            # Check if the user's role is allowed
            if user_role not in allowed_roles:
                return create_response(
                    message=NOT_AUTHORIZED_MESSAGE,
                    status_code=STATUS_CODES["forbidden"],
                )

            return func(*args, **kwargs)

        return wrapper

    return decorator


# Response related
def create_response(message: Dict, status_code: int) -> Response:
    """
    Create a response with a message and status code.

    params:
        message - The message to include in the response
        status_code - The HTTP status code to return

    returns:
        Response object with the message and status code

    raises:
        TypeError - If the message is not a dictionary or the status code is not an integer
    """

    if not isinstance(message, dict) and not (
        isinstance(message, list) and all(isinstance(item, dict) for item in message)
    ):
        raise TypeError("Message must be a dictionary or a list of dictionaries")
    if not isinstance(status_code, int):
        raise TypeError("Status code must be an integer")

    return make_response(jsonify(message), status_code)


def get_hateos_location_string(bp_name: str, id_: Union[str, int]) -> str:
    """
    Get the location string for HATEOAS links.

    Returns:
        str: The location string for HATEOAS links.
    """

    protocol = "https" if API_SERVER_SSL else "http"
    return (
        f"{protocol}://{API_SERVER_HOST}:{API_SERVER_PORT}{URL_PREFIX}{bp_name}/{id_}"
    )


def handle_options_request(resource_class) -> Response:
    """
    Handles OPTIONS requests for the resources.
    This method is used to determine the allowed HTTP methods for this resource.
    It returns a 200 OK response with the allowed methods in the Allow header.
    """

    # Ensure the input is a class
    if not inspect_isclass(resource_class):
        raise TypeError(
            f"resource_class must be a class, not an instance. Got {resource_class} instead."
        )

    # List of HTTP verbs to filter
    http_verbs = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
        "TRACE",
        "CONNECT",
    }

    # Define allowed methods
    allowed_methods = [
        verb for verb in http_verbs if hasattr(resource_class, verb.lower())
    ]

    # Create the response
    response = Response(status=STATUS_CODES["ok"])
    response.headers["Allow"] = ", ".join(allowed_methods)
    response.headers["Access-Control-Allow-Origin"] = "*"  # Adjust as needed for CORS
    response.headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


# Replace file-based rate-limiting with TTLCache
rate_limit_cache = TTLCache(
    maxsize=RATE_LIMIT_CACHE_SIZE, ttl=RATE_LIMIT_CACHE_TTL
)  # Cache with a TTL equal to the time window
rate_limit_lock = Lock()  # Lock for thread-safe file access


def is_rate_limited(client_ip: str) -> bool:
    """
    Check if the client IP is rate-limited using an in-memory TTLCache.
    """
    with rate_limit_lock:
        # Retrieve or initialize client data
        client_data = rate_limit_cache.get(client_ip, {"count": 0})

        # Increment the request count
        client_data["count"] += 1

        # Update the cache with the new client data
        rate_limit_cache[client_ip] = client_data

        # Check if the rate limit is exceeded
        return client_data["count"] > RATE_LIMIT_MAX_REQUESTS


# Database related
# Lazy initialization for the database connection pool
_DB_POOL: MySQLConnectionPool = (
    None  # Private variable to hold the connection pool instance
)


def get_db_pool():
    """
    Get the database connection pool instance, initializing it if necessary.
    """
    global _DB_POOL
    if (
        _DB_POOL is None
    ):  # Initialize only when accessed for the first time (lazy initialization)
        try:
            _DB_POOL = MySQLConnectionPool(
                pool_name="pctowa_connection_pool",
                pool_size=max(1, CONNECTION_POOL_SIZE),
                # Session reset not needed for this application (no transactions)
                pool_reset_session=False,
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
            )
        except socket.error as ex:
            print(
                f"Couldn't access database, see next line for full exception.\n{ex}\n"
                f"host: {DB_HOST}, dbname: {DB_NAME}, user: {DB_USER}, password: {DB_PASSWORD}\n"
                f"Make sure to shutdown all microservices with the provided kill_quick script, "
                f"change the configuration and try again.\n"
            )
            sys_exit(1)
    return _DB_POOL


# Function to get a connection from the pool
@contextmanager  # Make a context manager to ensure the connection is closed after use
def get_db_connection():
    """
    Get a database connection from the pool using lazy initialization.
    """
    connection = get_db_pool().get_connection()  # Use the lazily initialized pool
    try:
        yield connection
    finally:
        connection.close()


# Function to clear the connection pool
def clear_db_connection_pool():
    """
    Clear the database connection pool by closing all connections.
    """
    global _DB_POOL
    if _DB_POOL is not None:
        while True:
            try:
                connection = _DB_POOL.get_connection()
                connection.close()
            except Exception:
                break
        _DB_POOL = None


# Endpoint utility functions
def build_update_query_from_filters(
    data, table_name, pk_column, pk_value
) -> Tuple[str, List[Any]]:
    """
    Build a SQL update query from filters.

    params:
        data - The filters to apply to the query
        table_name - The name of the table to query
        pk_column - The name of the ID column to use for the update

    returns:
        A tuple containing the query and the parameters to pass to the query

    raises:
        None
    """

    # Remove keys with None values from the dictionary
    data = {key: value for key, value in data.items() if value is not None}

    filters = ", ".join([f"{key} = %s" for key in data.keys()])
    params = list(data.values()) + [pk_value]
    query = f"UPDATE {table_name} SET {filters} WHERE {pk_column} = %s"
    return query, params


def check_column_existence(
    modifiable_columns: List[str], to_modify: List[str]
) -> Union[Response, bool]:
    """
    Check if the columns to modify exist in the modifiable columns.
    If not, return an error response.
    If all columns are valid, return True.

    Params:
        modifiable_columns - The list of columns that can be modified
        to_modify - The list of columns to modify

    Returns:
        Response or bool - An error response if there are invalid columns,
                           or True if all columns are valid
    """

    error_columns = [field for field in to_modify if field not in modifiable_columns]

    # If there are any error columns, return an error response
    if error_columns:
        return f"error, field(s) {error_columns} do not exist or cannot be modified"

    # If all columns are valid, return True
    return True


# Database query related
def fetchone_query(query: str, params: Tuple[Any]) -> Union[Dict[str, Any], None]:
    """
    Execute a query on the database and return the result.

    params:
        query - The query to execute
        params - The parameters to pass to the query

    returns:
        The result of the query
    """

    # Use a context manager to ensure the connection is closed after use
    with get_db_connection() as connection:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(query, params)
            return cursor.fetchone()


def fetchall_query(query: str, params: Tuple[Any]) -> Union[List[Dict[str, Any]], None]:
    """
    Execute a query on the database and return the result.
    """

    with get_db_connection() as connection:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()


def execute_query(query: str, params: Tuple[Any]) -> Tuple[int, int]:
    """
    Execute a query on the database and commit the changes.

    params:
        query - The query to execute
        params - The parameters to pass to the query

    returns:
        The ID of the last inserted row, if applicable
        The number of rows affected by the query
    """
    # Use a context manager to ensure the connection is closed after use
    with get_db_connection() as connection:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(query, params)
            connection.commit()
            return cursor.lastrowid, cursor.rowcount


# Log server related
# Create a queue for log messages
log_queue = Queue()


def log_worker():
    """
    Background thread function to process log messages from the queue.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        # Get a log message from the queue
        log_data = log_queue.get()
        if log_data is None:  # Exit signal
            break

        # Extract log details
        type_, message, origin_name, origin_host, message_id, structured_data = log_data

        # Get the severity code for the log_type
        severity = SYSLOG_SEVERITY_MAP.get(type_, 6)  # Default to 'info' if not found

        # Format the syslog message with the correct priority
        priority = (1 * 8) + severity  # Assuming facility=1 (user-level messages)
        syslog_message = (
            f"<{priority}>1 "  #  # Priority
            # Timestamp in ISO 8601 format with timezone
            f"{datetime.now(timezone.utc).isoformat()} "
            f"{origin_host} "  # Hostname
            f"{origin_name} "  # App name
            f"{getpid()} "  # Process ID
            f"{message_id} "  # Message ID
            f"{structured_data} "  # Structured Data
            f"{message}"  # Log message
        )
        try:
            sock.sendto(
                syslog_message.encode("utf-8"), (LOG_SERVER_HOST, LOG_SERVER_PORT)
            )
        except socket.error as ex:
            print(f"Failed to send log: {ex}")

        # Mark the task as done
        log_queue.task_done()


# Start the background thread
log_thread = Thread(target=log_worker, daemon=True)
log_thread.start()


def log(
    message: str,
    log_type: str,
    origin_name: str = API_SERVER_NAME_IN_LOG,
    origin_host: str = API_SERVER_HOST,
    message_id: str = "UserAction",
    structured_data: Union[str, Dict[str, Any]] = "- -",
) -> None:
    """
    Add a log message to the queue for the background thread to process.
    """

    if isinstance(structured_data, Dict):
        structured_data = (
            "["
            + " ".join([f'{key}="{value}"' for key, value in structured_data.items()])
            + "]"
        )

    log_queue.put(
        (log_type, message, origin_name, origin_host, message_id, structured_data)
    )


# Graceful shutdown function to stop the log thread
def shutdown_logging():
    """
    Signal the log thread to exit and wait for it to finish.
    """
    log_queue.put(None)  # Send exit signal
