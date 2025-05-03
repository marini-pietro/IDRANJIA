"""
Utility functions for the API blueprints.
These functions include data validation, authorization checks, response creation,
database connection handling, logging, and token validation.
"""

import re
import inspect
import sys
import socket
import queue
import threading
from datetime import datetime, timezone
from os import getpid
from typing import Dict, List, Tuple, Any, Union
from functools import wraps
from contextlib import contextmanager
from flask import jsonify, make_response, Response, Request
from flask_jwt_extended import get_jwt
from mysql.connector.pooling import MySQLConnectionPool
from config import (
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_NAME,
    CONNECTION_POOL_SIZE,
    LOG_SERVER_HOST,
    LOG_SERVER_PORT,
    STATUS_CODES,
    ROLES,
    SYSLOG_SEVERITY_MAP,
    API_SERVER_HOST,
    API_SERVER_PORT,
    URL_PREFIX,
    API_SERVER_SSL,
)

# Data validation related
# Precompile the regex pattern once
SQL_PATTERN = re.compile(
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
        ]
    )
    + r")\b",
    re.IGNORECASE,
)


def is_input_safe(data: Union[str, List[str], Dict[Any, str]]) -> bool:
    """
    Check if the input data (string, list, or dictionary) contains SQL instructions.
    Returns True if safe, False if potentially unsafe.

    :param data: str, list, or dict - The input data to validate.
    :return: bool - True if the input is safe, False otherwise.
    """
    if isinstance(data, str):
        return not bool(SQL_PATTERN.search(data))
    if isinstance(data, list):
        return all(
            isinstance(item, str) and not bool(SQL_PATTERN.search(item))
            for item in data
        )
    if isinstance(data, dict):
        return all(
            isinstance(value, str) and not bool(SQL_PATTERN.search(value))
            for value in data.values()
        )
    else:
        raise TypeError(
            "Input must be a string, list of strings, or dictionary with string values."
        )


def has_valid_json(request_instance: Request) -> Union[str, Dict[str, Any]]:
    """
    Check if the request has a valid JSON body.

    :param request: The Flask request object.
    :return: str or dict - The JSON data if valid, or an error string if invalid.
    """
    if not request_instance.is_json or request_instance.json is None:
        return "Request body must be valid JSON with Content-Type: application/json"
    try:
        data = request_instance.get_json(silent=False)
        return data if data != {} else "Request body must not be empty"
    except ValueError:
        return "Invalid JSON format"


def validate_json_request(request_instance: Request) -> Union[str, Dict[str, Any]]:
    """
    Check that a request that should contain a JSON body has a valid JSON body and is safe from SQL injection.
    If the request is valid, return the JSON data.
    Otherwise, return an error message.
    """

    # Validate request
    data: Union[str, Dict[str, Any]] = has_valid_json(request_instance)
    if isinstance(data, str):
        return data

    # Check for sql injection
    if not is_input_safe(data):
        return "invalid input, suspected sql injection"

    # If the request is valid, return the data
    return data


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
            # Extract the role from the additional claims
            claims = get_jwt()
            user_role = claims.get("role")

            # Check if the user role is present in the token
            # If not, return an error response
            if user_role is None:
                return create_response(
                    {"error": "user role not present in token"},
                    STATUS_CODES["bad_request"],
                )

            # Check if the user's role is allowed
            if ROLES.get(user_role) not in allowed_roles:
                return create_response(
                    {"outcome": "not permitted"},
                    STATUS_CODES["forbidden"],
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
    if not inspect.isclass(resource_class):
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


# Data handling related
def parse_time_string(time_string: str) -> datetime:
    """
    Parse a time string in the format HH:MM and return a datetime object.

    params:
        time_string - The time string to parse

    returns:
        A datetime object if the string is in the correct format, None otherwise

    """

    try:
        return datetime.strptime(time_string, "%H:%M").time()
    except ValueError:
        return None


def parse_date_string(date_string: str) -> datetime:
    """
    Parse a date string in the format YYYY-MM-DD and return a datetime object.

    params:
        date_string - The date string to parse

    returns:
        A datetime object if the string is in the correct format, None otherwise

    """

    try:
        return datetime.strptime(date_string, "%Y-%m-%d").date()
    except ValueError:
        return None


# Database related
# Lazy initialization for the database connection pool
_DB_POOL: MySQLConnectionPool  = None  # Private variable to hold the connection pool instance


def get_db_pool():
    """
    Get the database connection pool instance, initializing it if necessary.
    """
    global _DB_POOL
    if _DB_POOL is None:  # Initialize only when accessed for the first time
        try:
            _DB_POOL = MySQLConnectionPool(
                pool_name="pctowa_connection_pool",
                pool_size=max(1, CONNECTION_POOL_SIZE),
                pool_reset_session=False,  # Session reset not needed for this application (no transactions)
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
            )
        except socket.error as ex:
            print(
                f"Couldn't access database, see next line for full exception.\n{ex}\n"
                f"host: {DB_HOST}, dbname: {DB_NAME}, user: {DB_USER}, password: {DB_PASSWORD}"
            )
            sys.exit(1)
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
        Response or bool - An error response if there are invalid columns, or True if all columns are valid
    """

    error_columns = [field for field in to_modify if field not in modifiable_columns]

    # If there are any error columns, return an error response
    if error_columns:
        return f"error, field(s) {error_columns} do not exist or cannot be modified"

    # If all columns are valid, return True
    return True

# Database query related
def fetchone_query(query: str, params: Tuple[Any]) -> Dict[str, Any]:
    """
    Execute a query on the database and return the result.

    params:
        query - The query to execute
        params - The parameters to pass to the query

    returns:
        The result of the query
    """

    with get_db_connection() as connection:  # Use a context manager to ensure the connection is closed after use
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(query, params)
            return cursor.fetchone()


def fetchall_query(query: str, params: Tuple[Any]) -> List[Dict[str, Any]]:
    """
    Execute a query on the database and return the result.
    """

    with get_db_connection() as connection:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()


def execute_query(query: str, params: Tuple[Any]) -> int:
    """
    Execute a query on the database and commit the changes.

    params:
        query - The query to execute
        params - The parameters to pass to the query

    returns:
        The ID of the last inserted row, if applicable
    """
    # Use a context manager to ensure the connection is closed after use
    with get_db_connection() as connection:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute(query, params)
            connection.commit()
            return cursor.lastrowid


# Log server related
# Create a queue for log messages
log_queue = queue.Queue()


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
            f"<{priority}>1 "
            f"{datetime.now(timezone.utc).isoformat()} "  # Timestamp in ISO 8601 format with timezone
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
log_thread = threading.Thread(target=log_worker, daemon=True)
log_thread.start()


def log(
    log_type: str,
    message: str,
    origin_name: str,
    origin_host: str,
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
    log_thread.join()  # Wait for the thread to finish (even if it is a daemon thread so no logs are lost)
