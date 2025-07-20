import json
from flask import Response, abort, make_response, request

from saq.json_encoding import _JSONEncoder


def json_request():
    if not request.json:
        abort(Response("Request must be in JSON format as dict.", 400))

    if not isinstance(request.json, dict):
        abort(Response("Request must be in JSON format as dict.", 400))

    return request.json
    
def json_result(data):
    response = make_response(json.dumps(data, cls=_JSONEncoder, sort_keys=True))
    response.mimetype = 'application/json'
    return response