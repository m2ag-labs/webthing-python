from datetime import datetime, timedelta
from pathlib import Path

from json import loads
from jwt import encode

# secret key in config
# if file read fails, create a file with a random string in it. (thing uses same file)
# secret can be any string
# enable false will bypass auth checks'''
try:
    #  with open(f'{str(Path.home())}/.m2ag-labs/secrets/jwt_secret.json', 'r') as file:
    with open(f'{str(Path.home())}/.webthings/things/jwt_secret.json', 'r') as file:
        opts = loads(file.read().replace('\n', ''))
        for i in opts:
            if i == 'secret':
                SECRET = opts[i]
except FileNotFoundError:
    print('Please run the sever with JWT enabled before using this script')
    quit()

AUTH_TTL = 31104000  # this is super long for development

"""
    Encode a new token with JSON Web Token (PyJWT)
"""
encoded = encode({
    'context': 'reserved for future use',
    'exp': datetime.utcnow() + timedelta(seconds=AUTH_TTL)},
    SECRET,
    algorithm='HS256'
)
# raspian desktop full -- this returns a buffer and needs to be decoded - currently pyjwt 1.7.0
# raspian lite -- returns a string -- version pyjwt 2.0.0
if isinstance(encoded, str):
    print(encoded)
else:
    print(encoded.decode('ascii'))
