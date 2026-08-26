# ABOUTME: Tests that credentials never survive into log output.
# ABOUTME: Gates the "tokens never logged" item in the SPEC security checklist.

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
