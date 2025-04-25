import re
import inspect
import socket
import threading
import traceback
from os import getpid
from datetime import datetime, timezone
from flask import jsonify, make_response, request, Response, Request
from flask_jwt_extended import get_jwt_identity
from contextlib import contextmanager
from mysql.connector import pooling as mysql_pooling
from datetime import datetime
from functools import wraps
from requests import post as requests_post
from cachetools import TTLCache
from typing import Dict, List, Tuple, Any, Union 
from config import (DB_HOST, DB_USER, DB_PASSWORD, 
                    DB_NAME, CONNECTION_POOL_SIZE, LOG_SERVER_HOST, 
                    LOG_SERVER_PORT, AUTH_SERVER_VALIDATE_URL, STATUS_CODES_EXPLANATIONS, 
                    STATUS_CODES, ROLES)

# Data validation related
# Precompile the regex pattern once
SQL_PATTERN = re.compile(
    r"\b(" + "|".join([
        r"SELECT", r"INSERT", r"UPDATE", r"DELETE", r"DROP", r"CREATE", r"ALTER",
        r"EXEC", r"UNION", r"ALL", r"WHERE", r"FROM", r"TABLE", r"JOIN", r"TRUNCATE",
        r"REPLACE", r"GRANT", r"REVOKE", r"DECLARE", r"CAST", r"SET"
    ]) + r")\b",
    re.IGNORECASE
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
    elif isinstance(data, list):
        return all(isinstance(item, str) and not bool(SQL_PATTERN.search(item)) for item in data)
    elif isinstance(data, dict):
        return all(isinstance(value, str) and not bool(SQL_PATTERN.search(value)) for value in data.values())
    else:
        raise TypeError("Input must be a string, list of strings, or dictionary with string values.")

def has_valid_json(request: Request) -> Union[str,  Dict[str, Any]]:
    """
    Check if the request has a valid JSON body.
    
    :param request: The Flask request object.
    :return: str or dict - The JSON data if valid, or an error string if invalid.
    """
    if not request.is_json or request.json is None:
        return 'Request body must be valid JSON with Content-Type: application/json'
    try:
        data = request.get_json(silent=False)
        return data if data != {} else 'Request body must not be empty'
    except ValueError as ex:
        return 'Invalid JSON format'

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
            # Extract the user's role from the JWT
            identity = get_jwt_identity()
            if not identity or 'role' not in identity:
                return create_response(
                    message={'outcome': 'not permitted: missing role or missing identity from jwt'}, 
                    status_code=STATUS_CODES["forbidden"]
                )
            
            user_role: int = identity['role']
            user_string: str = ROLES.get(user_role) # Get corresponding natural language name of roles (to allow for allowed_roles list to be the names of the roles and not their corresponding number)
            if user_string not in allowed_roles:
                return create_response(
                    message={'outcome': 'not permitted'}, 
                    status_code=STATUS_CODES["forbidden"]
                )
            
            # Proceed with the original function
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

    if not isinstance(message, Dict):
        raise TypeError("Message must be a dictionary")

    #message = f"{message}\n{STATUS_CODES_EXPLANATIONS.get(status_code, 'Unknown status code')}"

    return make_response(jsonify(message), status_code)

def get_class_http_verbs(class_: type) -> List[str]:
    """
    Args:
        class (type): The class to inspect. Must be a class object, not an instance.
    Returns:
        list[str]: A list of HTTP verbs (in uppercase) implemented as methods in the class.
    Raises:
        TypeError: If the provided argument is not a class.
    """
    # Ensure the input is a class
    if not inspect.isclass(class_):
        raise TypeError(f"class_ must be a class, not an instance. Got {class_} instead.")
    
    # List of HTTP verbs to filter
    http_verbs = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'}
    
    # Get all methods of the class and filter by HTTP verbs
    return [verb for verb in http_verbs if hasattr(class_, verb.lower())]

# Data handling related
def parse_time_string(time_string: str) -> datetime:
    """
    Parse a time string in the format HH:MM and return a datetime object.
    
    params:
        time_string - The time string to parse
    
    returns: 
        A datetime object if the string is in the correct format, None otherwise

    """

    try: return datetime.strptime(time_string, '%H:%M').time()
    except ValueError: return None

def parse_date_string(date_string: str) -> datetime:
    """
    Parse a date string in the format YYYY-MM-DD and return a datetime object.
    
    params:
        date_string - The date string to parse
    
    returns: 
        A datetime object if the string is in the correct format, None otherwise

    """

    try: return datetime.strptime(date_string, '%Y-%m-%d').date()
    except ValueError: return None

# Database related
# Lazy initialization for the database connection pool
_db_pool = None  # Private variable to hold the connection pool instance

def get_db_pool():
    global _db_pool
    if _db_pool is None:  # Initialize only when accessed for the first time
        try:
            _db_pool = mysql_pooling.MySQLConnectionPool(
                pool_name="pctowa_connection_pool",
                pool_size=max(1, CONNECTION_POOL_SIZE),
                pool_reset_session=False, # Session reset not needed for this application (no transactions)
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME
            )
        except Exception as ex:
            print(f"Couldn't access database, see next line for full exception.\n{ex}\n\nhost: {DB_HOST}, dbname: {DB_NAME}, user: {DB_USER}, password: {DB_PASSWORD}")
            exit(1)
    return _db_pool

# Function to get a connection from the pool
@contextmanager # Make a context manager to ensure the connection is closed after use
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
    for connection in _db_pool._cnx_queue:
        connection.close()
    _db_pool._cnx_queue.clear()

def build_select_query_from_filters(data, table_name, limit=1, offset=0): # TODO check if this function is necessary
    """
    Build a SQL query from filters.
    Does not support complex queries with joins or subqueries.

    params:
        data - The filters to apply to the query
        table_name - The name of the table to query
        limit - The maximum number of results to return
        offset - The offset for pagination
    
    returns:
        A tuple containing the query and the parameters to pass to the query

    raises:
        None
    """

    filters = " AND ".join([f"{key} = %s" for key in data.keys()])
    params = list(data.values()) + [limit, offset]
    query = f"SELECT * FROM {table_name} WHERE {filters} LIMIT %s OFFSET %s"
    return query, params

def build_update_query_from_filters(data, table_name, id_column, id_value) -> Tuple[str, List[Any]]:
    """
    Build a SQL update query from filters.
    
    params:
        data - The filters to apply to the query
        table_name - The name of the table to query
        id_column - The name of the ID column to use for the update
    
    returns:
        A tuple containing the query and the parameters to pass to the query

    raises:
        None
    """

    filters = ", ".join([f"{key} = %s" for key in data.keys()])
    params = list(data.values()) + [id_value]
    query = f"UPDATE {table_name} SET {filters} WHERE {id_column} = %s"
    return query, params

# Graceful shutdown handler
def shutdown_handler(signal, frame):
    clear_db_connection_pool()
    print("Database connection pool cleared. Exiting...")
    exit(0)

def fetchone_query(query: str, params: Tuple[Any]) -> Dict[str, Any]:
    """
    Execute a query on the database and return the result.
    
    params:
        query - The query to execute
        params - The parameters to pass to the query
        
    returns: 
        The result of the query
    """

    with get_db_connection() as connection: # Use a context manager to ensure the connection is closed after use
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
# Create an asynchronous session for log server interactions
def log(type: str, message: str, origin_name: str, origin_host: str, structured_data: str = "- -") -> None:
    """
    Send a log message to the syslog server asynchronously using threading.
    """
    def send_log():
        # Format the log message in RFC 5424 format
        syslog_message = (
            f"<14>1 "
            f"{datetime.now(timezone.utc).isoformat()} "  # Timestamp in ISO 8601 format with timezone
            f"{origin_host} "  # Hostname
            f"{origin_name} "  # App name
            f"{getpid()} "  # Process ID
            f"{structured_data} "  # Message ID and Structured Data
            f"{type.upper()}: {message}"  # Log type and message
        )

        print(f"{syslog_message}, len: {len(syslog_message)}")  # Debugging

        try:
            # Create a UDP socket and send the log message
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                print(f"Sending syslog message: {syslog_message}")  # Debugging
                sock.sendto(syslog_message.encode('utf-8'), (LOG_SERVER_HOST, LOG_SERVER_PORT))
        except Exception as ex:
            print(f"Failed to send log: {ex}")
            traceback.print_exc()

    # Run the log sending in a separate thread
    thread = threading.Thread(target=send_log, daemon=True)
    thread.start()
    thread.join()  # Wait for the thread to complete # Daemon thread will not block the program from exiting so it does not need to be waited (join command)

# Token validation related
# | Create a cache for token validation results with a time-to-live (TTL) of 300 seconds (5 minutes)
token_cache = TTLCache(maxsize=1000, ttl=300)

def jwt_required_endpoint(func: callable) -> callable:
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return create_response(message={'error': 'missing token'}, status_code=STATUS_CODES["unauthorized"])

        # Check token cache
        cached_result = token_cache.get(token)
        if cached_result:
            is_valid, identity = cached_result
        else:
            # Validate token with auth server
            headers = {'Authorization': f'Bearer {token}'}
            response = requests_post(AUTH_SERVER_VALIDATE_URL, headers=headers)

            if response.status_code != STATUS_CODES["ok"] or not response.json().get('valid'):
                return create_response(message={'error': 'Invalid or expired token'}, status_code=STATUS_CODES["unauthorized"])

            is_valid = response.json().get('valid')
            identity = response.json().get('identity')  # Extract the identity from the response
            token_cache[token] = (is_valid, identity)

        return func(*args, **kwargs)
    return wrapper