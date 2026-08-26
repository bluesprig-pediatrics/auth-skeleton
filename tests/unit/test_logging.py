# ABOUTME: Tests that credentials never survive into log output.
# ABOUTME: Gates the "tokens never logged" item in the SPEC security checklist.

import io
import logging

import pytest

from app.logging import RedactingFilter

SECRET = "s3cr3t-value-do-not-log"  # noqa: S105


def render(message, *args):
    record = logging.LogRecord("t", logging.INFO, __file__, 1, message, args, None)
    assert RedactingFilter().filter(record) is True
    return record.getMessage()


@pytest.mark.parametrize(
    "param",
    ["code", "id_token", "access_token", "refresh_token", "client_secret", "state"],
)
def test_query_parameter_is_redacted(param):
    out = render(f'GET /auth/callback?{param}={SECRET}&x=1 HTTP/1.1')
    assert SECRET not in out
    assert param in out
    assert "x=1" in out


def test_bearer_token_is_redacted():
    assert SECRET not in render(f"Authorization: Bearer {SECRET}")


def test_secret_in_args_is_redacted():
    assert SECRET not in render("callback %s", f"code={SECRET}")


def test_json_token_field_is_redacted():
    assert SECRET not in render(f'{{"access_token": "{SECRET}"}}')


def test_uvicorn_style_args_tuple_keeps_its_shape():
    """uvicorn's access formatter indexes args positionally; redaction must
    not change the tuple's length or the types it expects."""
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", f"/auth/callback?code={SECRET}", "1.1", 200),
        None,
    )
    assert RedactingFilter().filter(record) is True
    assert isinstance(record.args, tuple)
    assert len(record.args) == 5
    assert record.args[4] == 200
    assert SECRET not in record.getMessage()


def test_ordinary_message_survives_intact():
    assert render("user 42 signed in") == "user 42 signed in"


def test_format_placeholders_survive_redaction():
    """Redacting the format string would eat `%s` and make getMessage() raise,
    dropping the whole line. These are the OIDC paths the filter exists for."""
    for message, args in [
        ("token exchange failed code=%s", (400,)),
        ("id_token=%s issued", ("abc",)),
        ("state=%s", ("xyz",)),
    ]:
        record = logging.LogRecord("t", logging.INFO, __file__, 1, message, args, None)
        assert RedactingFilter().filter(record) is True
        record.getMessage()  # must not raise


@pytest.mark.parametrize(
    "message",
    ["status code: 200", "state: running", "HTTP status code 500", "exit code 1"],
)
def test_ordinary_prose_is_not_over_redacted(message):
    assert render(message) == message


def test_traceback_is_redacted():
    """exc_info is rendered by the formatter, after filters run. Pre-render it
    or an httpx error carrying the callback URL logs the authz code verbatim."""
    logger = logging.getLogger("test_traceback")
    logger.handlers.clear()
    logger.propagate = False
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    try:
        raise ValueError(f"GET /auth/callback?code={SECRET} failed")
    except ValueError:
        logger.exception("callback failed")
    assert SECRET not in stream.getvalue()


def test_trailing_delimiter_is_preserved():
    assert render(f"?code={SECRET};next") == "?code=[REDACTED];next"


def test_configure_logging_is_idempotent(caplog):
    from app.logging import configure_logging

    before = len(logging.getLogger("uvicorn.access").filters)
    configure_logging()
    configure_logging()
    assert len(logging.getLogger("uvicorn.access").filters) <= before + 1
