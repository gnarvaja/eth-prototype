import json
from urllib.parse import urlparse, urlunparse


def before_record_request(request):
    # Scrub the path and query string, which might contain credentials (alchemy, infura)
    scheme, netloc, path, params, query, fragment = urlparse(request.uri)
    request.uri = urlunparse((scheme, netloc, "", params, "", fragment))

    # Other common security-related concerns
    request.headers.pop("Authorization", None)

    return request


def json_rpc_matcher(r1, r2):
    assert r1.headers["Content-Type"] == r2.headers["Content-Type"] == "application/json"
    r1_body = json.loads(r1.body)
    r2_body = json.loads(r2.body)

    assert r1_body["jsonrpc"] == r2_body["jsonrpc"] == "2.0"
    assert r1_body["method"] == r2_body["method"]
    assert r1_body["params"] == r2_body["params"]
