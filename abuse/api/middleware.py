
import json
import sys

from datetime import datetime
from time import time

import jwt

from django import db
from django.db.utils import InterfaceError, OperationalError
from django.core.exceptions import ObjectDoesNotExist
from flask import g, request
from werkzeug.exceptions import BadRequest, Forbidden, Unauthorized

from .cache import RoleCache
from ..utils import crypto


UNAUTHENTICATED_ENDPOINTS = (
    'misc_views.auth',
    'misc_views.monitor'
)


def setup_middleware(api):

    from django.contrib.auth.models import User

    @api.before_request
    def set_stats_params():
        """
            Set stats parameters
        """
        # Set stats global vars
        g.start = time()
        if request.endpoint in api.view_functions:
            g.endpoint = api.view_functions[request.endpoint].__name__
        else:
            g.endpoint = 'not_handled'

    @api.before_request
    def check_db_conn():

        try:
            db_conn = db.connections['default']
            c = db_conn.cursor()
            c.execute('SELECT 1')
        except (InterfaceError, OperationalError):
            db.close_old_connections()

    @api.before_request
    def validate_json_body():
        """
            Check if there is a body for POST, PUT and PATCH methods
        """
        # Check json body
        if request.method in ('POST', 'PUT', 'PATCH'):
            try:
                request.get_json()
            except Exception:
                raise BadRequest('Missing or invalid body')

    @api.before_request
    def check_token():
        """
            Get login from HTTP header
        """
        if (request.method == 'OPTIONS' or
                request.endpoint and request.endpoint in UNAUTHENTICATED_ENDPOINTS or
                request.endpoint and request.endpoint.startswith('rq_dashboard.')):
            return

        valid, message = _check_headers()
        if not valid:
            raise Unauthorized(message)

        valid, message = _check_allowed_routes()
        if not valid:
            raise Forbidden(message)

    def _check_headers():

        try:
            token = request.environ['HTTP_X_API_TOKEN']
        except (KeyError, IndexError, TypeError):
            return False, 'Missing HTTP X-Api-Token header'

        try:
            data = jwt.decode(token, api.config['DJANGO']['SECRET_KEY'])
            data = json.loads(crypto.CryptoHandler.decrypt(str(data['data'])))
            user = User.objects.get(id=data['id'])
            g.user = user

            if user.last_login == datetime.fromtimestamp(0):
                return False, 'You need to login first'

            if user is not None and user.is_active:
                user.last_login = datetime.now()
                user.save()
                return True, None
        except (crypto.CryptoException, jwt.ExpiredSignature, jwt.DecodeError,
                User.DoesNotExist, KeyError):
            return False, 'Unable to authenticate'

    def _check_allowed_routes():

        try:
            role_codename = g.user.operator.role.codename
            is_valid = RoleCache.is_valid(
                role_codename,
                request.method,
                request.endpoint
            )
            if is_valid:
                return True, None
            return False, 'You are not allowed to {} {}'.format(
                request.method, request.path
            )
        except ObjectDoesNotExist:
            return False, 'You are not allowed to {} {}'.format(
                request.method, request.path
            )

    @api.after_request
    def after_request(response):
        """
            Log all requests
        """
        response.direct_passthrough = False
        length = sys.getsizeof(response.get_data())
        diff = int((time() - g.start) * 1000)

        api.logger.info({
            'request_method': request.method,
            'request_endpoint': request.endpoint,
            'request_url': request.url,
            'request_path': request.path,
            'request_query_args': request.args.to_dict(flat=False),
            'response_code': int(response.status_code),
            'response_length': length,
            'response_time': diff,
        })
        return response
