# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016, OVH SAS
#
# This file is part of Cerberus-core.
#
# Cerberus-core is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
    Decorators for Cerberus protected API.
"""

import sys
import traceback
from functools import wraps
from json import dumps

from django.db import DatabaseError, InterfaceError, OperationalError
from flask import Response, request
from flask.wrappers import BadRequest
from voluptuous import Invalid, MultipleInvalid, Schema
from werkzeug.contrib.cache import SimpleCache

from api.controllers import GeneralController
from utils import logger

Logger = logger.get_logger(__name__)

CACHE_TIMEOUT = 300
cache = SimpleCache()

Schemas = {}


class Cached(object):
    """ Return cached response, update if timeout
    """
    def __init__(self, timeout=None):
        self.timeout = timeout or CACHE_TIMEOUT

    def __call__(self, f):
        def decorator(*args, **kwargs):
            response = cache.get(unicode(request.path) + unicode(request.environ['HTTP_X_API_TOKEN']))
            if response is None:
                response = f(*args, **kwargs)
                cache.set(unicode(request.path) + unicode(request.environ['HTTP_X_API_TOKEN']), response, self.timeout)
            return response
        return decorator


def _reset_database_connection():
    """ Reset connection to DB
    """
    from django import db
    db.close_connection()


def _throw_exception(exception, message):
    """ Log exception and returns 500
    """
    exception_infos = sys.exc_info()
    exception_tb = traceback.extract_tb(exception_infos[2])
    exception_tb = exception_tb[-1]
    msg = "error - 'exception_type' %s - 'message' %s - 'exc_file' %s - 'exc_line' %s - 'exc_func' %s"
    msg = msg % (type(exception).__name__, str(exception), exception_tb[0], exception_tb[1], exception_tb[2])
    msg = msg.replace(':', '').replace('|', '')
    Logger.debug(unicode(msg))

    return 500, {'status': 'Internal Server Error', 'code': 500, 'message': message}


def token_required(func):
    """ Check HTTP Token
    """
    @wraps(func)
    def check_token(*args, **kwargs):
        valid, message = GeneralController.check_token(request)
        if not valid:
            return 401, {'status': 'Unauthorized', 'code': 401, 'message': message}
        return func(*args, **kwargs)
    return check_token


def admin_required(func):
    """ Check if user is admin
    """
    @wraps(func)
    def check_admin(*args, **kwargs):
        user = GeneralController.get_user(request)
        if not user.is_superuser:
            return 403, {'status': 'Forbidden', 'code': 403}
        return func(*args, **kwargs)
    return check_admin


def perm_required(func):
    """ Check if user can do actions
    """
    @wraps(func)
    def check_perm(*args, **kwargs):
        user = GeneralController.get_user(request)
        if 'report' in kwargs:
            code, resp = GeneralController.check_perms(method=request.method, user=user, report=kwargs['report'])
            if code != 200:
                return code, resp
        if 'ticket' in kwargs:
            code, resp = GeneralController.check_perms(method=request.method, user=user, ticket=kwargs['ticket'])
            if code != 200:
                return code, resp
        if 'defendant' in kwargs and request.method != 'GET':
            code, resp = GeneralController.check_perms(method=request.method, user=user, defendant=kwargs['defendant'])
            if code != 200:
                return code, resp
        return func(*args, **kwargs)
    return check_perm


def catch_500(func):
    """ Log Internal Server Error and return 500
    """
    @wraps(func)
    def check_exception(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BadRequest:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid JSON body'}
        except (DatabaseError, InterfaceError, OperationalError) as ex:
            _reset_database_connection()
            return _throw_exception(ex, 'Database connection lost, please retry')
        except Exception as ex:
            return _throw_exception(ex, 'Internal Server Error')
    return check_exception


def json_required(func):
    """ Decorator to validate JSON input
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            request.get_json()
        except Exception:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing or invalid body'}
        return func(*args, **kwargs)
    return wrapper


def jsonify(func):
    """ Make Json response
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        retval = func(*args, **kwargs)
        response = Response(dumps(retval[1]), status=retval[0], content_type='application/json')
        return response
    return decorated_function


def validate_body(schema_desc):
    """ Validate json body
    """
    def real_decorator(func):
        def wrapper(*args, **kwargs):
            try:
                body = request.get_json()
                if not Schemas.get(func.__name__):
                    Schemas[func.__name__] = Schema(schema_desc, required=True)
                    Logger.debug(unicode('registering schema for %s' % (func.__name__)))
                Schemas[func.__name__](body)
            except (Invalid, MultipleInvalid):
                return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing or invalid field(s) in body'}
            return func(*args, **kwargs)
        return wrapper
    return real_decorator
