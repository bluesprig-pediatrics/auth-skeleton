# ABOUTME: Logging filter that strips credentials from every log record.
# ABOUTME: Gates the "tokens never logged" item in the README security checklist.

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

_KEYS = "|".join(SENSITIVE_KEYS)

# `key=value` in a query string, form body, or cookie. The leading group
# anchors the key to a real delimiter: without it, `status code: 200` and
# `state: running` are redacted, erasing the values you need to debug an auth
# failure. `%` is excluded from the value so a `%s` placeholder is left alone —
# redacting it corrupts the format string and getMessage() then raises,
# dropping the entire line.
_PARAM = re.compile(rf"([?&]|\s|^)({_KEYS})=([^&\s;\"'%]+)", re.IGNORECASE)

# `"key": "value"` in a JSON body, which is how the token endpoint replies.
_JSON = re.compile(rf"(\"(?:{_KEYS})\"\s*:\s*\")([^\"]+)", re.IGNORECASE)

_BEARER = re.compile(r"(\bBearer\s+)([^\s\"';]+)", re.IGNORECASE)


def redact(text: str) -> str:
    text = _PARAM.sub(lambda m: f"{m[1]}{m[2]}={REDACTED}", text)
    text = _JSON.sub(lambda m: f"{m[1]}{REDACTED}", text)
    return _BEARER.sub(lambda m: f"{m[1]}{REDACTED}", text)


class RedactingFilter(logging.Filter):
    """Redacts credentials from a record's message, arguments, and traceback.

    Arguments are redacted in place rather than folded into the message:
    uvicorn's access formatter indexes `record.args` as a fixed-shape tuple, so
    collapsing it breaks the very log line this protects.

    `exc_info` is rendered by the formatter, which runs after filters. Setting
    `exc_text` here pre-empts that, because `logging.Formatter` reuses it when
    already populated — otherwise an httpx error carrying the callback URL
    writes the authorization code out verbatim.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(_redact_arg(arg) for arg in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: _redact_arg(val) for key, val in record.args.items()}
        if record.exc_info and not record.exc_text:
            record.exc_text = redact(_FORMATTER.formatException(record.exc_info))
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True


def _redact_arg(value: object) -> object:
    return redact(value) if isinstance(value, str) else value


_FORMATTER = logging.Formatter()

# One instance: logging.addFilter dedupes by identity, so a fresh object per
# call would append a filter to the uvicorn loggers on every create_app().
_FILTER = RedactingFilter()


def configure_logging() -> None:
    """Attach the redacting filter to the handlers that emit request data."""
    handler = logging.StreamHandler()
    handler.addFilter(_FILTER)
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    # uvicorn reconfigures logging after the app is built. dictConfig replaces
    # handlers but leaves logger-level filters, so attach at both levels.
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uvicorn_logger = logging.getLogger(name)
        for existing in uvicorn_logger.handlers:
            existing.addFilter(_FILTER)
        uvicorn_logger.addFilter(_FILTER)
