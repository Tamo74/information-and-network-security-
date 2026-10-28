import hashlib
import secrets

from ..common import RequestHandlerABC, RequestHandler, HeaderContainer, NO_CACHE_HEADERS
from ..http.request import HTTPRequest
from ..http.response import HTTPResponseFactory
from ..networking import ConnectionInfo


class DigestAuthMiddleware(RequestHandlerABC):
    def __init__(self, next: RequestHandler, pwdfile: str):
        self.next = next
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

        # Load users from the password file into a dict: username -> stored hash
        self.users = {}
        with open(pwdfile, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue  # skip blank/malformed lines rather than crashing
                username, _, pwd_hash = line.partition(":")
                self.users[username] = pwd_hash.strip()

        # Track the nonce(s) we've issued, so we can verify a client's
        # response was actually computed against a nonce we handed out
        self._issued_nonces = set()

    def __new_nonce(self) -> str:
        """Generate a fresh, unpredictable nonce and remember we issued it."""
        nonce = secrets.token_hex(16)
        self._issued_nonces.add(nonce)
        return nonce

    def __parse_digest_header(self, header_value: str) -> dict:
        """
        Parse a 'Digest key1="val1", key2="val2", ...' Authorization header
        into a dict. Returns {} if it doesn't look like a Digest header.
        """
        header_value = header_value.strip()
        if not header_value.lower().startswith("digest "):
            return {}

        fields = {}
        remainder = header_value[len("digest "):]
        for part in remainder.split(","):
            if "=" not in part:
                continue
            key, _, value = part.strip().partition("=")
            fields[key.strip()] = value.strip().strip('"')
        return fields

    def __verify_authorization(self, header_value: str) -> bool:
        fields = self.__parse_digest_header(header_value)

        username = fields.get("username")
        nonce = fields.get("nonce")
        response = fields.get("response")

        if not username or not nonce or not response:
            return False

        # Reject unknown users
        if username not in self.users:
            return False

        # reject nonces that were never issued defending against trivially replayed or fabricated requests
        if nonce not in self._issued_nonces:
            return False

        stored_hash = self.users[username]
        expected = hashlib.sha256(f"{stored_hash}:{nonce}".encode()).hexdigest()

        # constant time comparison to avoid leaking timing information
        return secrets.compare_digest(expected, response)

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        if "Authorization" in request.headers and self.__verify_authorization(
            request.headers["Authorization"]
        ):
            return self.next(conn_info, request)

        # issue a fresh nonce with every challenge
        nonce = self.__new_nonce()
        return self.http.status(
            401,
            HeaderContainer(
                {"WWW-Authenticate": f'Digest realm="auth", nonce="{nonce}"'}
            ),
        )