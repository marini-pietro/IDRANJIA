"""
This module handles the .env file (checking if it exists and loading it) and defines all
the configuration variables for the admin interface flask application in such a way that they are easily readable
from other parts of the code, which will see this file as a python module.
This module also provides default values and explanations for each configuration variable.
"""

# Library imports
from pathlib import Path
from dotenv import load_dotenv
from os import environ as os_environ

ENV_FILE = Path(__file__).resolve().with_name(".env")

if load_dotenv(dotenv_path=ENV_FILE):  # Loads .env file if present
    print(
        f"Admin interface configuration module: Loaded environment variables from {ENV_FILE}"
    )
else:
    print(
        f"Admin interface configuration module: No .env file found at {ENV_FILE}; using defaults and environment variables."
    )

ADMIN_INTERFACE_HOST: str = os_environ.get(
    "ADMIN_INTERFACE_HOST", "localhost"
)  # host on which the admin interface flask application listens for incoming requests
ADMIN_INTERFACE_PORT: int = int(
    os_environ.get("ADMIN_INTERFACE_PORT", 5000)
)  # port on which the admin interface flask application listens for incoming requests
ADMIN_INTERFACE_DEBUG: bool = os_environ.get(
    "ADMIN_INTERFACE_DEBUG", "False"
).lower() == "true" # whether the admin interface flask application runs in debug mode (True) or production mode (False)
ADMIN_INTERFACE_PAGING_SIZE: int = int(
    os_environ.get("ADMIN_INTERFACE_PAGING_SIZE", 20)
    )  # number of items per page in the admin interface
