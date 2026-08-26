# ABOUTME: Logging filter that strips credentials from every log record.
# ABOUTME: Gates the "tokens never logged" item in the SPEC security checklist.

import logging
import re

SENSITIVE_KEYS = (
    "code",
    "id_token",
    "access_token",
    "refresh_token",
    "client_secret",
    "state",
)

REDACTED = "[REDACTED]"

# Matches `key=value`, `key: value`, and `"key": "value"`. The value stops at
# the delimiters that end a query parameter, a JSON string, or a form field.
_KEY_VALUE = re.compile(
    r"\b(" + "|".join(SENSITIVE_KEYS) + r")(\"?\s*[=:]\s*\"?)([^\s&\"',}]+)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"\b(Bearer\s+)(\S+)", re.IGNORECASE)


def redact(text: str) -> str:
    text = _KEY_VALUE.sub(lambda m: f"{m[1]}{m[2]}{REDACTED}", text)
    return _BEARER.sub(lambda m: f"{m[1]}{REDACTED}", text)


class RedactingFilter(logging.Filter):
    """Redacts credentials from a record's message and its arguments.

    Arguments are redacted in place rather than folded into the message.
    uvicorn's access formatter indexes `record.args` as a fixed-shape tuple,
    so collapsing it breaks the log line it is meant to protect.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(_redact_arg(arg) for arg in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: _redact_arg(val) for key, val in record.args.items()}
        return True


def _redact_arg(value: object) -> object:
    return redact(value) if isinstance(value, str) else value


def configure_logging() -> None:
    """Attach the redacting filter to the handlers that emit request data."""
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    # uvicorn installs its own handlers; the access logger carries query strings.
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uvicorn_logger = logging.getLogger(name)
        for existing in uvicorn_logger.handlers:
            existing.addFilter(RedactingFilter())
        uvicorn_logger.addFilter(RedactingFilter())
