"""
    JSON Web Token auth for Tornado
    Modified by marc at m2ag.labs (marc@m2ag.net) from files found here:
    https://github.com/paulorodriguesxv/tornado-json-web-token-jwt
    Added configuration from file, errors as dict, added a check for
    websocket upgrade (wss add auth parameter to connect string --
    ?jwt=<token>)
"""
import jwt
import json
import socket
from pathlib import Path

"""
    Secret can be any string -- will be auto generated if jwt_secrets file does not exist
    Use the secret to generate the JWT.
    If it does not exist .m2ag-labs/secrets/jwt_config.json will be created.
    Setting enable false will signal the thing to bypass auth checks.
"""
CONFIG_FILE = 'jwt_config.json'
# CONFIG_PATH = f'{str(Path.home())}/.m2ag-labs/secrets'
CONFIG_PATH = f'{str(Path.home())}/.webthings/things'
OPTIONS = {
    'enable': True,
    'local_bypass': True,
    'secret_key': '',
    'auth_header': 'Authorization',
    'auth_param': 'jwt',
    'auth_error_code': 401,
    'auth_error_thing': {  # this needs to be json
        "id": "urn:m2ag:security:authorization-required",
        "title": f"{socket.gethostname()} is a secure thing. See https://{socket.gethostname()}.local:8443/auth.html",
        "@context": "https://webthings.io/schemas",
        "description": "Bearer tokens are required for this device",
        "securityDefinitions": {
            "bearer_sc": {
                "scheme": "bearer",
                "alg": "HS256",
                "description": "Security is required for this thing.",
                "authorization": f"https://{socket.gethostname()}.local:8443/auth.html"
            }
        },
        "security": ["bearer_sc"]
    },
    'jwt_options': {
        'verify_signature': True,
        'verify_exp': False,  # JWTs will never expire for this device if False
        'verify_nbf': False,
        'verify_iat': True,
        'verify_aud': False
    }
}


def get_options():
    try:
        with open(f'{CONFIG_PATH}/{CONFIG_FILE}', 'r') as file:
            opts = json.loads(file.read().replace('\n', ''))
            for i in opts:
                OPTIONS[i] = opts[i]
            del opts  # clean up

    except FileNotFoundError:
        import string
        import random

        rando = string.ascii_lowercase + string.digits
        OPTIONS['secret_key'] = ''.join(random.choice(rando) for i in range(100))

        Path(CONFIG_PATH).mkdir(parents=True, exist_ok=True)
        with open(f'{CONFIG_PATH}/{CONFIG_FILE}', 'w') as file:
            file.write(json.dumps(OPTIONS))


get_options()


def return_auth_error(handler, message):
    """
        Return authorization error
    """
    handler._transforms = []
    handler.set_status(OPTIONS['auth_error_code'])
    handler.write(OPTIONS['auth_error_thing'])
    handler.finish()


def return_header_error(handler):
    return_auth_error(handler, OPTIONS['auth_error_thing'])


def jwtauth(handler_class):
    # Tornado JWT Auth Decorator

    def wrap_execute(handler_execute):
        def require_auth(handler):
            # configure the jwt with a config file
            if not OPTIONS['enable']:
                return True
            # TODO: do we need to allow this?
            # makes same host access harder
            if OPTIONS['local_bypass'] and handler.request.remote_ip == '127.0.0.1':
                return True
            auth = handler.request.headers.get(OPTIONS['auth_header'])
            if auth:
                parts = auth.split()
                try:
                    jwt.decode(
                        parts[1],
                        OPTIONS['secret_key'],
                        algorithms=["HS256"],
                        options=OPTIONS['jwt_options']
                    )
                except Exception as err:
                    print(str(err))
                    return_auth_error(handler, OPTIONS['auth_error_thing'])

            else:
                # is this websocket upgrade? if so look for auth header in
                # params
                upgrade = handler.request.headers.get("Upgrade")
                if upgrade == 'websocket':
                    # broken up for length issue (flake8)
                    handle = handler.request.query_arguments
                    auth = handle.get(OPTIONS['auth_param'])
                    if auth:
                        try:
                            jwt.decode(
                                auth[0].decode('UTF-8'),
                                OPTIONS['secret_key'],
                                algorithms=["HS256"],
                                options=OPTIONS['jwt_options']
                            )
                        except Exception as err:
                            print(str(err))
                            return_auth_error(handler, OPTIONS['auth_error_thing'])
                        return True

                handler._transforms = []
                handler.write(OPTIONS['auth_error_thing'])
                handler.finish()

            return True

        def _execute(self, transforms, *args, **kwargs):

            try:
                require_auth(self)
            except Exception:
                return False

            return handler_execute(self, transforms, *args, **kwargs)

        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class
