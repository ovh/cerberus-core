#!/usr/bin/env python
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
    API for Cerberus UX

    This file defines many classes customizing Flask app
"""

import json
import sys
import time
import traceback

from datetime import datetime
from time import mktime

# Init settings

import django
from django.conf import ImproperlyConfigured

try:
    django.setup()
    from django.conf import settings
except ImproperlyConfigured:
    from django.conf import global_settings, settings
    from config import settings as custom_settings

    for attr in dir(custom_settings):
        if not callable(getattr(custom_settings, attr)) and not attr.startswith("__"):
            setattr(global_settings, attr, getattr(custom_settings, attr))

    settings.configure()
    django.setup()

import jwt

from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from flask import Flask, g, jsonify, request, Response
from werkzeug.exceptions import (BadRequest, default_exceptions, Forbidden,
                                 HTTPException, Unauthorized)

from factory.implementation import ImplementationFactory
from utils import logger, utils


CRYPTO = utils.Crypto()
RoleCache = utils.RoleCache()
UNAUTHENTICATED_ENDPOINTS = (
    'misc_views.auth',
    'misc_views.monitor'
)


class JSONExceptionHandler(object):

    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def std_handler(self, error):
        response = jsonify(
            code=error.code,
            status=error.name,
            message=error.description
        )
        response.status_code = error.code if isinstance(error, HTTPException) else 500
        return response

    def init_app(self, app):
        self.app = app
        self.register(HTTPException)
        for code, v in default_exceptions.iteritems():
            self.register(code)

    def register(self, exception_or_code, handler=None):
        self.app.errorhandler(exception_or_code)(handler or self.std_handler)


class TimestampJSONEncoder(json.JSONEncoder):
    """
        JSONEncoder subclass that convert datetime to timestamp
    """
    def default(self, obj):
        if isinstance(obj, datetime):
            timestamp = int(mktime(obj.timetuple()))
            return timestamp
        else:
            return super(TimestampJSONEncoder, self).default(obj)


class CerberusResponse(Response):  # pylint: disable=too-many-ancestors
    """
        This class wraps FlasK/Werkzeug Response to handle Json
    """
    @classmethod
    def force_type(cls, rv, environ=None):
        if isinstance(rv, dict) or isinstance(rv, list):
            rv = Response(
                json.dumps(
                    rv,
                    cls=TimestampJSONEncoder,
                ),
                content_type='application/json'
            )
        return super(CerberusResponse, cls).force_type(rv, environ)


class CerberusApp(Flask):
    """
        This class set Flask Response to `api.api.CerberusResponse`
    """
    response_class = CerberusResponse


def create_app():
    """
        Initialize Flask application
    """
    from views.categories import category_views
    from views.defendants import defendant_views
    from views.email_templates import email_templates_views
    from views.misc import misc_views
    from views.news import news_views
    from views.presets import preset_views
    from views.providers import provider_views
    from views.reports import report_views
    from views.reputations import reputation_views
    from views.tags import tag_views
    from views.tickets import ticket_views
    from views.thresholds import threshold_views

    app = CerberusApp(__name__)
    JSONExceptionHandler(app)
    app.register_blueprint(category_views)
    app.register_blueprint(defendant_views)
    app.register_blueprint(email_templates_views)
    app.register_blueprint(preset_views)
    app.register_blueprint(misc_views)
    app.register_blueprint(news_views)
    app.register_blueprint(provider_views)
    app.register_blueprint(report_views)
    app.register_blueprint(reputation_views)
    app.register_blueprint(tag_views)
    app.register_blueprint(ticket_views)
    app.register_blueprint(threshold_views)

    @app.before_request
    def set_stats_params():
        """
            Set stats parameters
        """
        # Set stats global vars
        g.start = time.time()
        if request.endpoint in APP.view_functions:
            g.endpoint = APP.view_functions[request.endpoint].__name__
        else:
            g.endpoint = 'not_handled'

    @app.before_request
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

    @app.before_request
    def check_token():
        """
            Get login from HTTP header
        """
        if request.method == 'OPTIONS' or request.endpoint in UNAUTHENTICATED_ENDPOINTS:
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
            data = jwt.decode(token, settings.SECRET_KEY)
            data = json.loads(CRYPTO.decrypt(str(data['data'])))
            user = User.objects.get(id=data['id'])
            g.user = user

            if user.last_login == datetime.fromtimestamp(0):
                return False, 'You need to login first'

            if user is not None and user.is_active:
                user.last_login = datetime.now()
                user.save()
                return True, None
        except (utils.CryptoException, jwt.ExpiredSignature, jwt.DecodeError,
                User.DoesNotExist, KeyError):
            return False, 'Unable to authenticate'

    def _check_allowed_routes():

        try:
            role_codename = g.user.operator.role.codename
            is_valid = RoleCache.is_valid(role_codename, request.method, request.endpoint)
            if is_valid:
                return True, None
            return False, 'You are not allowed to %s %s' % (request.method, request.path)
        except ObjectDoesNotExist:
            return False, 'You are not allowed to %s %s' % (request.method, request.path)

    @app.after_request
    def after_request(response):
        """
            Log all requests
        """
        response.direct_passthrough = False
        method = request.method
        path = request.path
        http_code = int(response.status_code)
        length = sys.getsizeof(response.get_data())
        diff = int((time.time() - g.start) * 1000)

        log_msg = '%s %s => generated %d bytes in %d msecs (HTTP/1.1 %d)'
        Logger.debug(
            unicode(log_msg % (method, path, length, diff, http_code)),
            extra={
                'http_endpoint': g.endpoint,
                'http_path': path,
                'http_length': length,
                'http_time_int': diff,
                'http_code': http_code,
            }
        )
        if ImplementationFactory.instance.is_implemented('KPIServiceBase'):
            ImplementationFactory.instance.get_singleton_of(
                'KPIServiceBase'
            ).new_api_request(
                g.endpoint,
                http_code,
                diff,
            )
        return response

    @app.errorhandler(Exception)
    def unhandled_exception(exception):
        """
            Log exception and returns 500
        """
        _reset_database_connection()
        exception_infos = sys.exc_info()
        exception_tb = traceback.extract_tb(exception_infos[2])[-1]
        msg = "error - 'exc_type' {} - 'msg' {} - 'exc_file' {} - 'exc_line' {} - 'exc_func' {}"
        msg = msg.format(
            type(exception).__name__,
            str(exception),
            exception_tb[0],
            exception_tb[1],
            exception_tb[2]
        )
        msg = msg.replace(':', '').replace('|', '')
        Logger.debug(unicode(msg))

        return {'message': 'Internal Server Error'}, 500

    def _reset_database_connection():
        """
            Reset connection to DB
        """
        from django import db
        db.close_connection()

    return app

APP = create_app()
Logger = logger.get_logger(__name__)


if __name__ == '__main__':

    APP.run(host=settings.API['host'], port=settings.API['port'])
