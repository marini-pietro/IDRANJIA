# IDRANJIA

This repository provides a compact microservice-style Flask application for managing the backend of the IDRANJIA application and its related resources.  
The IDRANJIA project is aimed at providing fire fighters, public workers and hydrants mantainers with a quick, reliable, secure, easy to use/access browser based platform to access and manage hydrant related data.  
Most probably the platform will also be accessible through a mobile wrapper application.

## High level architecture

- `api_server.py` — main HTTP API that registers blueprints, configures JWT validation and OpenAPI docs (Flasgger). It exposes application endpoints implemented in `api_blueprints/`.
  
- `auth_server.py` — dedicated authentication microservice that verifies passwords and issues JWT access and refresh tokens. It contains the login, token validation and refresh endpoints.

- `log_server.py` — UDP syslog-like listener that parses incoming syslog messages, performs rate-limiting, and writes structured output to file and console.

Shared components and important files

- `models.py` — SQLAlchemy models for domain objects.  
Each model includes a `to_dict()` helper for JSON serialization.

- `config.py` — centralized configuration values (jwt settings, DB URI, regex patterns, rate limit parameters, file names and ports).  
Many defaults are development-friendly; override them before production.

- `api_blueprints/` — collection of Flask blueprints and utilities.  
Each blueprint corresponds to a logical resource (hydrant, control, photo, operator, user). `blueprints_utils.py` contains common helpers (logging, rate-limiting utilities, input validation helpers).
  
- `tests/` — pytest suites covering the microservices and blueprints.

## Security measures

This project implements several security measures. Highlights below reference the code and the config values in `config.py`.

- Password hashing and verification
	- Passwords are stored and validated using PBKDF2-HMAC-SHA256 (`PBKDF2HMAC`) with 100k iterations and a 32-byte length. The verification function in `auth_server.py`:
		- Expects a `salt:hash` base64-encoded format.
		- Validates base64 decoding and handles malformed inputs gracefully.
		- Uses `kdf.verify(...)` to avoid timing [side-channel attacks](https://en.wikipedia.org/wiki/Side-channel_attack) that could arise from naive comparisons. (Naive byte-by-byte check returns as soon a mismatch is found, because of this attacker can measure timing differences to recover secrets. To resolve this a constant-time comparison method is needed)

- JWT authentication
	- `flask_jwt_extended` is used for issuing and validating tokens.
	- Access token lifetime is configurable (`JWT_ACCESS_TOKEN_EXPIRES`) and refresh tokens are separate (`JWT_REFRESH_TOKEN_EXPIRES`).
	- The project performs a runtime check that `JWT_SECRET_KEY` has at least 32 bytes when encoded in UTF-8, long secrets are preferable but a short one won't stop the application.
	- The application checks tokens from multiple locations (headers, query string, and JSON) but you should avoid `query_string` in production to tokens leaking in logs.

- Input validation and SQL-injection scanning
	- A precompiled regex named `SQL_PATTERN` in `config.py` is used to detect common SQL keywords and suspicious characters. Functions like `is_input_safe()` (in `auth_server.py`) and blueprint-level checks validate incoming JSON keys and values.
	- Note: This scanning is a helpful heuristic but not a replacement for parameterized queries. All DB access should use SQLAlchemy ORM or parameterized queries (SQLAlchemy handles that by default).
	- To avoid ReDos a maximum length for a scannable string and maximum recursion depth (for scanning complex data types that may contain other contain complex data types and so on) are defined (configurable via `.env` file).

- Rate limiting
	- Rate limit is enforced using TTL (Time to live) cache shared across all services and blueprints, if services are separated in different machine cache implementation may have to change.
    - Related settings are configurable in `config.py`.
	- The log server additionally can queue delayed messages rather than dropping them immediately when the rate-limit triggers (especially with low limits the rate limiting may trigger even if there is no DDoS related behaviour, just heavy traffic. In such case it would be desirable that even if the rate limit triggers the messages are still kept in consideration and not discarded but, on the other hand, allowing these kinds of logs to be eventually written into the log file may clutter up the log file in the end and/or reduce its reliability if an actual DDoS attack happens. There is no perfectly suitable way to satisfy both possibilities so user will just have to make an educated guess by tweaking limits and/or disabling this retention of messages received after rate limiting has been triggered by editing the `.env` file).

- Logging and monitoring
	- Centralized logging via `log_server.py` and helper logging functions in `api_blueprints/blueprints_utils.py`.
	- Structured logs include server name and host and optionally a message id / structured data field.

- Transport security (TLS)
	- `api_server.py` and `auth_server.py` support SSL if certificate and key paths are provided in `config.py` (`*_SSL_CERT`, `*_SSL_KEY`, and `*_SSL` flags).

## Configuration and secrets (what to review before production)

- To streamline the process of separating the services into different machines, a config file has been created for each server. In a testing/development environment these virtually function as a single monolithic configuration file.
Unavoidably, there is some overlap between some of the configuration files, these always have to match the other configuration/settings.
- Verify and replace any default secrets and DB credentials in `*_config.py` with secure values.
- Confirm token lifetimes and locations are suited to your deployment. Avoid `query_string` token locations in public-facing environments.

- The `*.config.py` files centralize default settings. Sensitive values in the repo (like the default `JWT_SECRET_KEY` and DB credentials) are for convenience in local development only. For production, you should:
	- Replace `JWT_SECRET_KEY` with a long, randomly generated secret (recommended >= 32 bytes). Use an environment variable or secret manager.
	- Use secure DB credentials and restrict DB network access.
	- Disable `API_SERVER_DEBUG_MODE` and `AUTH_SERVER_DEBUG_MODE` in production.

Recommended environment overrides (examples):

- `JWT_SECRET_KEY` — use a securely generated key (e.g., 32+ bytes from `openssl rand -base64 48`).
- `SQLALCHEMY_DATABASE_URI` — use a production DB URI rather than the local defaults.

# Rough road map to move into production

- Review test coverage.
- Remove any sensitive/weak settings that may affect security.
- Depending on the number of machines you are deploying to, separate each service with their relevant  `*_config.py` file and a suitable `.env` file. (If a machine runs two or more services all the relevant `*_config.py` file have to present and the `.env` file has to be the sum of all the relevant `.env` files).
- Using admin utilities (still being worked on) test that all the security measures function properly.

## Troubleshooting pointers

- Common JWT issue: mismatched `JWT_SECRET_KEY` or `JWT_ALGORITHM` between `auth_server.py` and `api_server.py`.  
- Authentication failures: verify the stored password format and PBKDF2 parameters (iterations, hash length).  
- Logging/Rate-limit: check `config.py` rate limit values and the log server's delayed queue size if messages are dropped.  
- Unable to load configuration: The suffix .example has not been removed from the .env file.  
- Unable to execute quick start/kill scripts to run the code on Windows based machines: Execute this command in the powershell terminal `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`, this will allow script execution only for the current terminal sessions and not affect any other sessions or system-wide settings.
- Unable to execuite quick start/kill scripts to run the code on Linux based machines: Ensure the scripts have the proper permission (i.e you have properly used the `chmod` command).
- Terminal looks cramped and arduos to read while testing/developing: Because of the testing/developing environment most element of the architecture will run on the same machine, naturally, as a result, all the output messages will mix together and become hard to read. Because of Powershell text formatting, the issue overall being minor and the code required to fix it not worth implementing no solution is provided for this problem.

## Security hardening checklist (recommended before production)

1. Remove any hard-coded secret or sensitive settings and put them inside of a properly managed and kept `.env` file.
2. Ensure `JWT_SECRET_KEY` >= 32 bytes, rotate periodically, and keep secrets out of source control.
3. Use real TLS certificates in `*_SSL_CERT` / `*_SSL_KEY` (`*_SSL` flags will automatically configure wether certificate and key are provided or not).
4. Use a managed database or secure DB instance with restricted network access and strong credentials.
5. Disable debug modes and remove overly permissive token locations (prefer headers over query string).
