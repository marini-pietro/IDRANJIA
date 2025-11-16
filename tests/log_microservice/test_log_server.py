from api_blueprints import blueprints_utils as bu
import log_server

# This file contains unit tests for the functions and features defined in log_server.py


def test_enforce_rate_limit_counters():
    # Clear the shared rate limit cache to reset environment
    bu.rate_limit_cache.clear()
    CLIENT_IP = "1.2.3.4"  # Arbitrary client IP for testing
    max_req = (
        log_server.RATE_LIMIT_MAX_REQUESTS
    )  # Get max requests from log_server (defined in config file originally)

    # Calls up to max_req should not exceed; the (max_req+1)-th should
    for i in range(max_req):
        assert log_server.enforce_rate_limit(CLIENT_IP) is False
    assert log_server.enforce_rate_limit(CLIENT_IP) is True


def test__process_message_parsing_and_logging(monkeypatch):
    # Replace logger with a dummy to capture calls
    calls = []

    class DummyLogger:
        def log(self, log_type, message, origin):
            calls.append((log_type, message, origin))

        def close(self):
            pass

    monkeypatch.setattr(log_server, "logger", DummyLogger())

    # A valid RFC 5424 message: priority 14 -> 14 % 8 == 6 -> 'info'
    msg = "<14>1 2020-01-01T00:00:00Z localhost app 123 ID47 - Test message"
    addr = ("127.0.0.1", 514)
    log_server._process_message(msg, addr)
    assert len(calls) >= 1
    assert calls[0][0] == "info"

    # Invalid message should log a warning
    calls.clear()
    bad_msg = "this is not a syslog message"
    log_server._process_message(bad_msg, addr)
    assert len(calls) >= 1
    assert calls[0][0] == "warning"
