# ABOUTME: A minimal real OIDC issuer used by the Entra client tests.
# ABOUTME: Serves JWKS and a token endpoint over HTTP so nothing is mocked out.

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

KID = "test-key-1"

# Generated once. A 2048-bit keygen per test dominated the suite's runtime.
_SHARED_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeIdP:
    """Serves a real JWKS document and a real token endpoint.

    Counts JWKS fetches, which is how the bounded-refetch requirement is
    asserted rather than assumed.
    """

    def __init__(self, *, use_other_key: bool = False) -> None:
        self.key: RSAPrivateKey = _OTHER_KEY if use_other_key else _SHARED_KEY
        self.jwks_fetches = 0
        self.token_response: dict[str, Any] = {}
        self.token_status = 200
        self.last_token_request: dict[str, str] = {}
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        # poll_interval: shutdown() waits for the next poll, and the 0.5s default
        # made teardown dominate the suite.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def jwks_document(self) -> dict[str, Any]:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}

    def sign(self, claims: dict[str, Any], *, kid: str = KID, algorithm: str = "RS256") -> str:
        key = "" if algorithm == "none" else self.key
        return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid})  # type: ignore[arg-type]

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                """Silence. Test output must stay pristine."""

            def do_GET(self) -> None:
                if self.path.endswith("/keys"):
                    idp.jwks_fetches += 1
                    self._json(200, idp.jwks_document())
                else:
                    self._json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode()
                idp.last_token_request = dict(
                    part.split("=", 1) for part in body.split("&") if "=" in part
                )
                self._json(idp.token_status, idp.token_response)

            def _json(self, status: int, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        return Handler
