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
"""

import inspect
import json
import os
import sys
import time
import traceback

from datetime import datetime

CURRENTDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PARENTDIR = os.path.dirname(CURRENTDIR)
sys.path.insert(0, PARENTDIR)

import django
import jwt
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from flask import Flask, g, jsonify, request

from factory.factory import ImplementationFactory
from utils import logger, utils


CRYPTO = utils.Crypto()


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

    app = Flask(__name__)
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
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                request.get_json()
            except Exception:
                return jsonify({'status': 'Bad Request', 'code': 400, 'message': 'Missing or invalid body'}), 400

    @app.before_request
    def check_token():
        """
            Get login from HTTP header
        """
        if request.method == 'OPTIONS':
            return

        if request.endpoint in ['misc_views.auth', 'misc_views.monitor']:
            return

        valid, message = _check_headers()
        if not valid:
            return jsonify({'status': 'Unauthorized', 'code': 401, 'message': message}), 401

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
        except (utils.CryptoException, jwt.ExpiredSignature, jwt.DecodeError, User.DoesNotExist, KeyError):
            return False, 'Unable to authenticate'

        try:
            return g.user.operator.role.allowedRoutes.filter(method=request.method, endpoint=request.endpoint).exists(), None
        except ObjectDoesNotExist:
            return False, 'You are not allowed to %s %s' % (request.method, request.path)

        return True, None

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
        msg = "error - 'exception_type' %s - 'message' %s - 'exc_file' %s - 'exc_line' %s - 'exc_func' %s"
        msg = msg % (type(exception).__name__, str(exception), exception_tb[0], exception_tb[1], exception_tb[2])
        msg = msg.replace(':', '').replace('|', '')
        Logger.debug(unicode(msg))

        return jsonify({'status': 'Internal Server Error', 'code': 500, 'message': 'Internal Server Error'}), 500

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
