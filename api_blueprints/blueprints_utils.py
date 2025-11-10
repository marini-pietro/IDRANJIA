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
from threading import Lock, Thread
from typing import Any, Dict, List, Union

from cachetools import TTLCache
from flask import Response, jsonify, make_response, request
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
        token = None
        auth_header = request.headers.get("Authorization", None)
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "", 1)

        # If the token is not in the Authorization header, check the query string
        if not token:
            token = request.args.get(JWT_QUERY_STRING_NAME, None)

        # If the token is not in the query string, check the JSON body
        if not token:
            json_body = request.get_json(silent=True)  # Safely get JSON body
            if json_body:  # Ensure it's not None
                token = json_body.get(JWT_JSON_KEY, None)

        # Validate the token
        if not token:
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
                    timeout=5,  # in seconds
                )

                # If the token is invalid, return a 401 Unauthorized response
                if response.status_code != STATUS_CODES["ok"]:
                    return {"error": "Invalid token"}, STATUS_CODES["unauthorized"]
                else:
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
                return {"error": "Login request timed out"}, STATUS_CODES[
                    "gateway_timeout"
                ]

            except RequestException as ex:
                log(
                    log_type="error",
                    message=f"Error validating token: {ex}",
                    origin_name="JWTValidation",
                    origin_host=API_SERVER_HOST,
                )
                return {
                    "error": "internal server error while validating token"
                }, STATUS_CODES["internal_error"]

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
        log_type, message, origin_name, origin_host, message_id, structured_data = (
            log_data
        )

        # Get the severity code for the log_type
        severity = SYSLOG_SEVERITY_MAP.get(
            log_type, 6
        )  # Default to 'info' if not found

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
    log_type: str,
    message: str,
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
