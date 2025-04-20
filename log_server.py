import logging
from flask import Flask, request, jsonify
from os.path import abspath as os_path_abspath
from os.path import dirname as os_path_dirname
from os.path import join as os_path_join
from api_blueprints.blueprints_utils import has_valid_json
from typing import Dict, Any, Union
from config import (LOG_SERVER_HOST, LOG_SERVER_PORT, 
                    LOG_SERVER_DEBUG_MODE, LOG_FILE_NAME, 
                    LOGGER_NAME, STATUS_CODES,
                    LOG_SERVER_NAME_IN_LOG)

# Create a Flask application
app = Flask(__name__)

# Define the logger class
class Logger:
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
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        # Add handlers to the logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    # Function to log messages with different levels (automatically retrieves the right function based on the log type parameter)
    # The log_type parameter should be one of the logging levels: debug, info, warning, error, critical
    def log(self, log_type, message, origin):
        """
        Log a message with the specified type, message and origin
        """

        log_method = getattr(self.logger, log_type)
        log_method(f"[{origin}] {message}")

    # Function to close all handlers
    def close(self):
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)

# Generate the log file path so that it is in the same directory as this script
log_file_path: str = os_path_join(os_path_dirname(os_path_abspath(__file__)), LOG_FILE_NAME)

# Initialize the logger
logger = Logger(log_file=log_file_path, console_level=logging.INFO, file_level=logging.DEBUG)

@app.route('/log', methods=['POST'])
def log_message():
    """
    Endpoint to log messages.
    Expects a JSON payload with 'type', 'message', and 'origin'.
    """

    # Validate the request data
    data: Union[str, Dict[str, Any]] = has_valid_json(request)
    if isinstance(data, str):
        return jsonify({"error": data}), STATUS_CODES["bad_request"]
    
    # Gather data from the request
    log_type: str = data.get("type", "info")
    message: str = data.get("message")
    origin: str = data.get("origin", "unknown")

    # Validate the data
    if not message:
        return jsonify({"error": "Message value required"}), STATUS_CODES["bad_request"]
    if log_type not in ["debug", "info", "warning", "error", "critical"]:
        return jsonify({"error": "invalid log type"}), STATUS_CODES["bad_request"]
    if not isinstance(origin, str):
        return jsonify({"error": "Origin value must be a string"}), STATUS_CODES["bad_request"]

    try: 
        logger.log(log_type, message, origin)
    except Exception as ex: 
        # Log the error if logging fails
        logger.log(log_type="error", 
                   message=f"Unable to log message: {ex}", 
                   origin=LOG_SERVER_NAME_IN_LOG)

        # Return an error response if logging fails
        return jsonify({"error": f"unable to log"}), STATUS_CODES["internal_error"]

    # Return a success response
    return jsonify({"status": "success"}), STATUS_CODES["ok"]

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint to verify the server is running.
    """
    return jsonify({"status": "ok"}), STATUS_CODES["ok"]

if __name__ == "__main__":
    try:
        app.run(host=LOG_SERVER_HOST, 
                port=LOG_SERVER_PORT, 
                debug=LOG_SERVER_DEBUG_MODE)
    except KeyboardInterrupt:
        logger.close()