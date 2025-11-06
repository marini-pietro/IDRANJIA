"""
Syslog server implementation that listens for syslog messages over UDP.
It processes messages according to RFC 5424, implements rate limiting,
and logs messages to both console and file.
It also handles delayed logs when the rate limit is exceeded.
"""

# Import necessary libraries
import socket
import re
import logging
import time
import threading
from collections import defaultdict, deque
from threading import Thread, Lock
from os.path import abspath as os_path_abspath
from os.path import dirname as os_path_dirname
from os.path import join as os_path_join
from config import (
    LOG_SERVER_HOST,
    LOG_SERVER_PORT,
    LOG_FILE_NAME,
    LOGGER_NAME,
    RATE_LIMIT_MAX_REQUESTS,
    DELAYED_LOGS_QUEUE_SIZE,
    LOG_SERVER_RATE_LIMIT,
)
from api_blueprints.blueprints_utils import (
    rate_limit_cache,
    rate_limit_lock,
)


# Define the logger class
class Logger:
    """
    Logger class to handle logging messages to both console and file.
    """

    def __init__(self, log_file, console_level, file_level):
        # Create a logger object
        self.logger: Logger = logging.getLogger(name=LOGGER_NAME)
        self.logger.setLevel(logging.DEBUG)

        # Create a console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)

        # Create a file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(file_level)

        # Create formatter objects and set the format of the log messages
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        # Add handlers to the logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    # Function to log messages with different levels
    # (automatically retrieves the right function based on the log type parameter)
    # The log_type parameter should be one of the logging levels:
    # debug, info, warning, error, critical
    def log(self, log_type, message, origin):
        """
        Log a message with the specified type, message and origin
        """

        log_method = getattr(self.logger, log_type)
        log_method(f"[{origin}] {message}")

    # Function to close all handlers
    def close(self):
        """
        Close all handlers of the logger.
        """
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)


# Generate the log file path so that it is in the same directory as this script
log_file_path: str = os_path_join(
    os_path_dirname(os_path_abspath(__file__)), LOG_FILE_NAME
)

# Initialize the logger
logger = Logger(
    log_file=log_file_path, console_level=logging.INFO, file_level=logging.DEBUG
)

# Add a shutdown flag
shutdown_flag = threading.Event()


def start_syslog_server(host, port):
    """
    Start a syslog server that listens for messages over UDP.
    """
    syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create a UDP socket
    try:
        syslog_socket.bind((host, port)) # Bind to the specified host and port
    except OSError as e:
        print(f"Failed to bind UDP socket on {host}:{port}: {e}")
        print(
            "Is another instance of the log server already running or is the port in use?"
        )
        return
    print(f"Syslog server listening on {host}:{port}")

    try:
        while not shutdown_flag.is_set():  # Check the shutdown flag
            syslog_socket.settimeout(
                1.0
            )  # Set a timeout to periodically check the flag
            try:
                data, addr = syslog_socket.recvfrom(1024) # Buffer size is 1024 bytes
                message = data.decode("utf-8") # Decode the received bytes to string
                process_syslog_message(message, addr) # Process the received message
            except socket.timeout:
                continue  # Continue to next iteration if no data is received
    except KeyboardInterrupt:
        print("Shutting down syslog server...")
    finally:
        shutdown_flag.set()  # Signal the background thread to stop
        syslog_socket.close()
        logger.close()


# Compile the RFC 5424 syslog message regex pattern once
SYSLOG_PATTERN = re.compile(
    r"<(\d+)>"  # PRI
    r"(\d{1,2}) "  # VERSION
    r"(\S+) "  # TIMESTAMP
    r"(\S+) "  # HOSTNAME
    r"(\S+) "  # APP-NAME
    r"(\S+) "  # PROCID
    r"(\S+) "  # MSGID
    r"(\[.*?\]|-) "  # STRUCTURED-DATA
    r"(.*)"  # MSG
)

# Dictionary to track message counts and timestamps per source
message_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})

# Queue to store delayed logs
delayed_logs = deque(
    maxlen=DELAYED_LOGS_QUEUE_SIZE
)  # Limit the size of the queue to avoid memory issues
queue_lock = Lock()  # Lock to ensure thread-safe access to the queue


def enforce_rate_limit(client_ip: str) -> bool:
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


def process_syslog_message(message, addr):
    """
    Process and log a syslog message according to RFC 5424 with shared rate limiting.
    """
    source_ip = addr[0]

    # Enforce rate limit
    if LOG_SERVER_RATE_LIMIT is True:
        if enforce_rate_limit(source_ip):
            # Add the log to the delayed queue instead of dropping it
            with queue_lock:
                delayed_logs.append((message, addr))
            logger.log(
                "warning",
                f"Rate limit exceeded for {source_ip}. Delaying message: {message}",
                f"Syslog-{source_ip}",
            )
            return  # Do not process the message immediately

    # Process the syslog message as usual
    _process_message(message, addr)


def _process_message(message, addr):
    """
    Helper function to process a syslog message.
    """
    match = SYSLOG_PATTERN.match(message)
    if match:
        # Extract fields from the syslog message
        priority = int(match.group(1))
        version = match.group(2)
        timestamp = match.group(3)
        hostname = match.group(4)
        app_name = match.group(5)
        proc_id = match.group(6)
        msg_id = match.group(7)
        structured_data = match.group(8)
        msg_content = match.group(9)

        # Map priority to log level
        log_level = {
            0: "critical",
            1: "alert",
            2: "critical",
            3: "error",
            4: "warning",
            5: "notice",
            6: "info",
            7: "debug",
        }.get(
            priority % 8, "info"
        )  # Default to "info" if unknown

        # Log the message with detailed information
        logger.log(
            log_type=log_level,
            message=(
                f"{timestamp} {hostname} {app_name} {proc_id} "
                f"{msg_id} {structured_data} {msg_content}"
            ),
            origin=f"sourceIP-{addr[0]}",
        )
    else:
        # Log a warning for invalid syslog messages
        logger.log("warning", f"Invalid syslog message: {message}", f"Syslog-{addr[0]}")


def process_delayed_logs():
    """
    Periodically process delayed logs from the queue.
    """
    while not shutdown_flag.is_set():  # Check the shutdown flag
        with queue_lock:
            if delayed_logs:
                message, addr = delayed_logs.popleft()
                _process_message(message, addr)
        time.sleep(0.1)  # Adjust the sleep interval as needed


# Start a background thread to process delayed logs
Thread(target=process_delayed_logs, daemon=True).start()

if __name__ == "__main__":
    start_syslog_server(LOG_SERVER_HOST, LOG_SERVER_PORT)
