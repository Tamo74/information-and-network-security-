#import to calculate SHA-256 hashes
import hashlib

#import to extract nonce from server's challenge
import re

#import to send HTTP reqs
import urllib.request

#imports to handle HTTP + connection errs
from urllib.error import HTTPError, URLError


def send_request(url, authorisation=None):
    #create HTTP GET req for requested URL
    request = urllib.request.Request(url, method="GET")

    #add Authorisation header if authentication info is provided
    if authorisation is not None:
        request.add_header("Authorization", authorisation)

    try:
        #send req + read server's response
        with urllib.request.urlopen(request, timeout=10) as response:
            return (
                response.status,
                response.headers,
                response.read()
            )

    except HTTPError as error:
        #HTTPError is raised for responses eg 401 Unauthorized
        #return status, headers + body so the challenge can be read
        return (
            error.code,
            error.headers,
            error.read()
        )


def start_client():
    #ask user which resource they want to retrieve
    url = input(
        "Enter the URL (press Enter for homepage): "
    ).strip()

    #use local server homepage if the user enters no URL
    if not url:
        url = "http://127.0.0.1:8080/"

    #ask user for their login credentials
    username = input("Username: ")
    password = input("Password: ")

    #send first req w/o authentication -> server should respond with 401 Digest challenge
    status, headers, body = send_request(url)

    #stop if server did not issue an authentication challenge
    if status != 401:
        print(f"HTTP status: {status}")
        print(body.decode("utf-8", errors="replace"))
        return

    #read authentication challenge from response headers
    challenge = headers.get("WWW-Authenticate", "")

    #extract nonce from the Digest challenge
    match = re.search(r'nonce="([^"]+)"', challenge)

    #check that the challenge uses Digest + includes a nonce
    if not challenge.lower().startswith("digest ") or not match:
        print("The server did not provide a valid Digest challenge.")
        print(f"HTTP status: {status}")
        return

    #save the nonce provided by the server
    nonce = match.group(1)

    #hash password using SHA-256
    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    #calc the response expected by the supplied middleware
    response_hash = hashlib.sha256(
        f"{password_hash}:{nonce}".encode("utf-8")
    ).hexdigest()

    #build Authorization header in the format expected by the server
    authorisation = (
        f'Digest username="{username}", '
        f'nonce="{nonce}", '
        f'response="{response_hash}"'
    )

    #retry the req w the calculated authentication response
    status, headers, body = send_request(url, authorisation)

    #display the final HTTP status code
    print(f"HTTP status: {status}")

    #display returned page content
    print(body.decode("utf-8", errors="replace"))


#run client when this file is executed directly
if __name__ == "__main__":
    try:
        start_client()
    except (URLError, TimeoutError, OSError) as error:
        #display connection errs w/o a Python traceback
        print(f"Could not connect to the server: {error}")
