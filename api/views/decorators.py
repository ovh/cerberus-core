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

from functools import wraps
from json import dumps

from flask import g, Response, request
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


def admin_required(func):
    """ Check if user is admin
    """
    @wraps(func)
    def check_admin(*args, **kwargs):
        if not g.user.operator.role.codename == 'admin':
            return 403, {'status': 'Forbidden', 'code': 403, 'message': 'Forbidden'}
        return func(*args, **kwargs)
    return check_admin


def perm_required(func):
    """ Check if user can do actions
    """
    @wraps(func)
    def check_perm(*args, **kwargs):
        if 'report' in kwargs:
            code, resp = GeneralController.check_perms(method=request.method, user=g.user, report=kwargs['report'])
            if code != 200:
                return code, resp
        if 'ticket' in kwargs:
            code, resp = GeneralController.check_perms(method=request.method, user=g.user, ticket=kwargs['ticket'])
            if code != 200:
                return code, resp
        if 'defendant' in kwargs and request.method != 'GET':
            code, resp = GeneralController.check_perms(method=request.method, user=g.user, defendant=kwargs['defendant'])
            if code != 200:
                return code, resp
        return func(*args, **kwargs)
    return check_perm


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
