import json
from logging import raiseExceptions
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'dev-bc6endsx.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffeeshop'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
#    raise Exception('Not Implemented')

    header = request.headers.get('Authorization')
    if not header:
        raise AuthError({
            'description': 'Autherization header missing'
        })
 

    split_header = header.split(' ')

    if split_header[0].lower() != "bearer":
          raise AuthError({
                'description': 'Invalid Header Token'
            })
    
    if len(split_header) == 1:
          raise AuthError({
                'description': 'Invalid Header'
            })

    if len(split_header) > 2:
         raise AuthError({
                'description': 'Invalid Header'
            })
    
    header_token = split_header[1]

    return header_token


'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    # raise Exception('Not Implemented')
    if permission not in payload['permissions']:
     raise AuthError({
                'description': 'Authorization not granted'
            })
    if 'permissions' not in payload:
          raise AuthError({
                'description': 'Invalid permission claims'
            })

    return True
'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(header_token):
    url = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')

    jwts = json.loads(url.read())

    invalid_header = jwt.get_unverified_header(header_token)

    rsa = {}
    if "kid" not in invalid_header:
        raise AuthError({
                'description': 'Invalid Header'
            })

    for key in jwts["keys"]:
        if key['kid'] == invalid_header['kid']:
            rsa = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa:
        try:
            payload = jwt.decode(
                header_token,
                rsa,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
                raise AuthError({
                'description': 'The Token has expired'
            })
        except  Exception:
            raise AuthError({
                'description': 'Unable to authenticate'
            })
    raise AuthError({
        'description': 'Unable to find key'
    })

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator