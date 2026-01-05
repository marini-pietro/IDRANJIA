"""
Syslog server implementation that listens for syslog messages over UDP.
It processes messages according to RFC 5424, implements rate limiting,
and logs messages to both console and file.
It also handles delayed logs when the rate limit is exceeded.
"""

# Library imports
import re as regex_lib
import logging
import time
import threading
import selectors
import socket as socket_lib
from datetime import datetime
from collections import defaultdict, deque
from typing import List, Tuple, Deque, Optional, Pattern, Match
from threading import Thread, Lock
from cachetools import TTLCache
from os.path import abspath as os_path_abspath
from os.path import dirname as os_path_dirname
from os.path import join as os_path_join

# Local imports
from log_config import (
    LOG_SERVER_HOST,
    LOG_SERVER_PORT,
    LOG_FILE_NAME,
    LOGGER_NAME,
    LOG_SERVER_IDENTIFIER,
    LOG_SERVER_RATE_LIMIT,
    DELAYED_LOGS_QUEUE_SIZE,
    RETAIN_LOGS_RATE_LIMIT_TRIGGER,
    RETAIN_LOGS_RATE_LIMIT_TRIGGER,
    LOG_RATE_LIMIT_TRIGGER_EVENTS,
    LOG_SERVER_RATE_LIMIT_MAX_REQUESTS,
    LOG_SERVER_RATE_LIMIT_CACHE_SIZE,
    LOG_SERVER_RATE_LIMIT_CACHE_TTL,
)

# Replace file-based rate-limiting with TTLCache
rate_limit_cache = TTLCache(
    maxsize=LOG_SERVER_RATE_LIMIT_CACHE_SIZE, ttl=LOG_SERVER_RATE_LIMIT_CACHE_TTL
)  # Cache with a TTL equal to the time window
rate_limit_lock = Lock()  # Lock for thread-safe file access

# Define the logger class
class Logger:
    """
    Logger class to handle logging messages to both console and file.
    """

    def __init__(self, log_file: str, console_level: int, file_level: int) -> None:
        """
        Initialize the logger with console and file handlers.
        """
        # Create a logger object
        self.logger: logging.Logger = logging.getLogger(name=LOGGER_NAME)
        self.logger.setLevel(logging.DEBUG)
        # Prevent log messages from being propagated to the root logger (avoids duplicates)
        self.logger.propagate = False

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

        # Add handlers to the logger only if they are not already present
        if not self.logger.handlers:
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)

    # Function to log messages with different levels
    # (automatically retrieves the right function based on the log type parameter)
    # The log_type parameter should be one of the logging levels:
    # debug, info, warning, error, critical
    def log(self, log_type: str, message: str, origin: str) -> None:
        """
        Log a message with the specified type, message and origin.
        """

        log_method = getattr(
            self.logger, log_type
        )  # Get the logging method based on log_type
        log_method(
            f"[{origin}] {message}"
        )  # Call the method to log the message with origin info

    # Function to close all handlers
    def close(self) -> None:
        """
        Close all handlers of the logger.
        """

        for handler in self.logger.handlers[:]: # [:] copies the list to avoid modification during iteration
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
shutdown_flag: threading.Event = threading.Event()


def start_syslog_server(host: str, port: int) -> None:
    """
    Start a UDP-based syslog server that listens on both IPv4 and IPv6 addresses.
    This function attempts to bind two dedicated UDP sockets (one IPv6, one IPv4)
    for the provided host and port and then uses a selectors.DefaultSelector to
    monitor them for incoming datagrams. Each successfully bound socket is set to
    non-blocking mode and registered with the selector for read events so the
    selector will notify the loop when there is data available to be read from the
    socket.
    Behavior and features:
    - Resolves and binds addresses using socket.getaddrinfo(..., AI_PASSIVE), trying
        IPv6 first then IPv4.
    - The main loop polls the selector with a 1 second timeout and exits when the
        global shutdown_flag is set (or on KeyboardInterrupt).
    - Incoming datagrams are received with recvfrom(65535). Data is decoded as UTF-8;
        if decoding fails, invalid sequences are replaced and a warning is emitted via
        logger.log with an origin identifying the source IP.
    - Received messages are handed off to process_syslog_message(message, addr) for
        application-level handling.
    - Socket and selector errors during recvfrom are skipped (socket remains in use).
    - On shutdown, the function sets shutdown_flag, unregisters and closes all
        sockets, closes the selector, and calls logger.close() to tidy up resources.
    Parameters:
    - host (str | None): The local interface or hostname to bind to (may be None or
        "" to bind all interfaces).
    - port (int | str): The UDP port (or service name) to listen on.
    Return value:
    - None. The function runs a blocking polling loop until shutdown_flag is set or
        a KeyboardInterrupt occurs.
    """

    socket_selector = selectors.DefaultSelector()
    sockets: List[Optional[socket_lib.socket]] = []

    # Helper to attempt bind for a specific address family
    def _bind_for_family(family: int) -> Optional[socket_lib.socket]:
        try:
            addrinfos = socket_lib.getaddrinfo(
                host=host,
                port=port,
                family=family,
                type=socket_lib.SOCK_DGRAM,
                flags=socket_lib.AI_PASSIVE,
            )
        except socket_lib.gaierror:
            return None

        # Try each address until bind operations is successful
        for (
            ip_address_family,
            _,
            _,
            _,
            server_addr,
        ) in addrinfos:  # _ represents ignored values not used in this context
            try:
                socket = socket_lib.socket(ip_address_family, socket_lib.SOCK_DGRAM)
                # On IPv6, try to allow dual-stack where supported (this doesn't replace two-socket approach)
                if ip_address_family == socket_lib.AF_INET6:
                    try:
                        socket.setsockopt(
                            socket_lib.IPPROTO_IPV6, socket_lib.IPV6_V6ONLY, 0
                        )
                    except Exception:
                        pass
                socket.bind(server_addr)  # Bind the socket to the address
                return socket  # Return the successfully bound socket
            except OSError:
                try:
                    socket.close()  # Close the socket on failure
                except Exception:
                    pass
                continue
        return None

    # Try to create both IPv6 and IPv4 sockets (IPv6 first)
    ipv6_socket = _bind_for_family(socket_lib.AF_INET6)
    ipv4_socket = _bind_for_family(socket_lib.AF_INET)

    # Add the successfully bound sockets to the list of available sockets
    if ipv6_socket:
        sockets.append(ipv6_socket)
    if ipv4_socket:
        sockets.append(ipv4_socket)

    # Print binding status
    if ipv6_socket and ipv4_socket:
        print(f"Syslog server bound to both IPv6 and IPv4, listening on {host}:{port}")
    elif ipv6_socket and not ipv4_socket:
        print(f"Syslog server bound to IPv6 only, listening on {host}:{port}")
    elif ipv4_socket and not ipv6_socket:
        print(f"Syslog server bound to IPv4 only, listening on {host}:{port}")
    if not sockets:
        print(
            f"Failed to bind both UDP sockets on {host}:{port}\nIs another instance of the log server already running or is the port in use?"
        )
        return

    for socket in sockets:
        socket.setblocking(
            False
        )  # Make socket non-blocking (I/O calls won't block the thread execution)
        socket_selector.register(
            socket, selectors.EVENT_READ
        )  # Register socket for read events

    try:
        while not shutdown_flag.is_set():
            events = socket_selector.select(timeout=1.0)
            if not events:  # If there are no events, continue to the next iteration
                continue
            for key, _ in events:
                sock = key.fileobj # Get the socket object from the selector key
                try:
                    # Receive data from the socket
                    data, addr = sock.recvfrom(
                        65535
                    )  # buffer size set to maximum UDP size to reduce risk of truncation
                    # UPD related fragmentation can still occur; handling of fragmented messages is not implemented
                except OSError:
                    # Socket error — skip this socket for now
                    continue
                try:
                    message = data.decode("utf-8")  # Decode as UTF-8
                except (
                    UnicodeDecodeError
                ):  # If decoding fails, replace invalid sequences
                    message = data.decode("utf-8", errors="replace")
                    logger.log(  # Log a warning about the decoding issue
                        log_type="warning",
                        message=(
                            "Received non-UTF8 bytes from client — replaced invalid sequences "
                            f"in message: {message}"
                        ),
                        origin=f"source_ip={addr[0]}",
                    )

                # Hand off the message to the processing function
                process_syslog_message(message, addr)

    except KeyboardInterrupt:
        print("Shutting down syslog server...")
    # Regardless of how we exit the loop, ensure all resources are cleaned up
    finally:
        shutdown_flag.set()  # Set the shutdown flag so that the loop in the threads can exit gracefully
        for socket in sockets:
            try:
                socket_selector.unregister(
                    socket
                )  # Unregister the socket from the selector
            except Exception:  # Ignore errors during unregistering
                pass
            try:
                socket.close()  # Close the socket
            except Exception:  # Ignore errors during socket close
                pass
        try:
            socket_selector.close()  # Close the selector
        except Exception:  # Ignore errors during selector close
            pass
        logger.close()  # Close the logger


# Compile the RFC 5424 syslog message regex pattern once
# Full pattern breakdown:
# <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
# Note: This pattern does not capture the entire RFC 5424 spec (e.g., NILVALUE handling,
# timestamp formats, etc.) but provides a basic structure for common messages.
# Note: Pattern is set to greedy matching for MSG to capture the full remaining payload.
SYSLOG_PATTERN: Pattern[str] = regex_lib.compile(
    r"<(\d+)>"  # PRI
    r"(\d{1,2}) "  # VERSION
    r"(\S+) "  # TIMESTAMP
    r"(\S+) "  # HOSTNAME
    r"(\S+) "  # APP-NAME
    r"(\S+) "  # PROCID
    r"(\S+) "  # MSGID
    # STRUCTURED-DATA: either '-' or one-or-more SD-ELEMENTs like [id ...][id2 ...]
    r"((?:\[[^\]]*\])|-)"
    r"\s(.*)"  # MSG (remaining payload)
)

# Dictionary to track message counts and timestamps per source
message_counts = defaultdict(lambda: {"count": 0, "timestamp": time.time()})

# Queue to store delayed logs
delayed_logs: Deque[Tuple[str, tuple]] = deque(
    maxlen=DELAYED_LOGS_QUEUE_SIZE
)  # Limit the size of the queue to avoid memory issues
queue_lock = Lock()  # Lock to ensure thread-safe access to the queue


def enforce_rate_limit(client_ip: str) -> bool:
    """
    Check if the client IP is rate-limited using an in-memory TTLCache.  
    (This function will return true (the rate has been exceeded) on the exact request that matches the limit, i.e. the 100th request is the limit is 100 requests per time window)
    """

    with rate_limit_lock:
        # Retrieve or initialize client data
        client_data = rate_limit_cache.get(client_ip, {"count": 0})

        # Increment the request count
        client_data["count"] += 1

        # Update the cache with the new client data
        rate_limit_cache[client_ip] = client_data

        # Check if the rate limit is exceeded
        return client_data["count"] > LOG_SERVER_RATE_LIMIT_MAX_REQUESTS


def process_syslog_message(message: str, addr: tuple) -> None:
    """
    Process and log a syslog message according to RFC 5424 with shared rate limiting.

    Parameters
    ----------
    message:
        Decoded syslog message (expected RFC 5424-like format).
    addr:
        Remote address tuple as returned by socket.recvfrom (ip, port, ...).

    Returns
    -------
    None
    """

    source_ip = addr[0]  # Extract source IP from address tuple

    # Enforce rate limit
    if LOG_SERVER_RATE_LIMIT is True:
        if enforce_rate_limit(source_ip):
            # Add the log to the delayed queue instead of dropping it (if enabled)
            if RETAIN_LOGS_RATE_LIMIT_TRIGGER is True:
                with queue_lock:
                    delayed_logs.append((message, addr))
                    
            # Log the rate limit event if enabled
            if LOG_RATE_LIMIT_TRIGGER_EVENTS is True:
                logger.log(
                    log_type="warning",
                    message=f"{source_ip} exceeded rate limit. Delaying message: {message}",
                    origin=f"source_ip={source_ip}",
                )

            return

    # Process the syslog message as usual
    _process_message(message, addr)


def _process_message(message: str, addr: tuple) -> None:
    """
    Helper function to parse and log a single syslog message.

    This function assumes `message` is a decoded string and `addr` is the
    address tuple from recvfrom(). It will parse the message using
    SYSLOG_PATTERN and emit structured logs via `logger`.
    """
    match: Optional[Match[str]] = SYSLOG_PATTERN.match(message)
    if match:
        # Extract priority and validate
        raw_priority = match.group(1)
        try:
            priority = int(raw_priority)  # Convert PRI to integer
        except (ValueError, TypeError, OverflowError):
            # Non-numeric PRI — log a warning and default to a safe informational priority
            logger.log(
                log_type="warning",
                message=(
                    f"Invalid PRI received: {raw_priority}; expected integer 0-191. "
                    "Defaulting to informational severity."
                ),
                origin=f"source_ip={addr[0]}",
            )
            priority = 5  # default to Notice/Informational

        # Validate numeric PRI is within RFC allowed range (0..191)
        if not (0 <= priority <= 191):
            logger.log(
                log_type="warning",
                message=(
                    f"PRI value out of range: {raw_priority}; expected 0-191. "
                    "Defaulting to informational severity."
                ),
                origin=f"source_ip={addr[0]}",
            )
            priority = 5  # default to Notice/Informational

        # Extract remaining fields
        version = match.group(2)
        timestamp = match.group(3)
        hostname = match.group(4)
        app_name = match.group(5)
        proc_id = match.group(6)
        msg_id = match.group(7)
        structured_data = match.group(8)
        msg_content = match.group(9)

        # Validate timestamp (accept RFC5424 NILVALUE "-" as valid)
        def _is_valid_rfc3339(timestamp: str) -> bool:
            if timestamp == "-" or timestamp is None:
                return True
            s = timestamp
            # datetime.fromisoformat does not accept 'Z' for UTC, convert it to +00:00
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            try:
                # fromisoformat supports YYYY-MM-DDTHH:MM:SS[.ffffff][+HH:MM]
                datetime.fromisoformat(s)
                return True
            except Exception:
                return False

        if not _is_valid_rfc3339(timestamp):  # Validate timestamp format
            logger.log(
                log_type="warning",
                message=f"Invalid RFC3339 timestamp received: {timestamp}",
                origin=f"source_ip={addr[0]}",
            )

        # Map RFC 5424 severity (priority % 8) to Python logging methods
        # RFC severities: 0=Emergency,1=Alert,2=Critical,3=Error,4=Warning,5=Notice,6=Informational,7=Debug
        # Map Notice/Informational to 'info' and Emergency/Alert/Critical to 'critical'
        log_level = {
            0: "critical",
            1: "critical",
            2: "critical",
            3: "error",
            4: "warning",
            5: "info",
            6: "info",
            7: "debug",
        }.get(
            priority % 8, "info"
        )  # Default to "info" if unknown

        # Log the message with detailed information
        logger.log(
            log_type=log_level,
            message=(
                f"<{priority}> {version} {timestamp} {hostname} {app_name} {proc_id} "
                f"{msg_id} {structured_data} {msg_content}"
            ),
            origin=f"source_ip={addr[0]}",
        )
    else:
        # Log a warning for invalid syslog messages
        logger.log(
            log_type="warning",
            message=f"Invalid syslog message: {message}",
            origin=f"source_ip={addr[0]}",
        )


def process_delayed_logs() -> None:
    """
    Periodically process delayed logs from the queue.

    This background worker will dequeue delayed messages and process them
    with the same parsing/validation logic as real-time messages. It exits
    when `shutdown_flag` is set.
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

    # Log server startup event
    logger.log(
        log_type="info",
        message="Starting syslog server...",
        origin=LOG_SERVER_IDENTIFIER,
    )

    try:
        # Start the syslog server
        start_syslog_server(LOG_SERVER_HOST, LOG_SERVER_PORT)

    except KeyboardInterrupt:
        logger.log(
            log_type="info",
            message="Syslog server stopped by user via KeyboardInterrupt.",
            origin=LOG_SERVER_IDENTIFIER,
        )
    except Exception as ex:
        logger.log(
            log_type="warning",
            message=f"Syslog server encountered stopped with exception: {ex}",
            origin=LOG_SERVER_IDENTIFIER,
        )
