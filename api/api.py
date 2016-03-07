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
import os
import sys
import time

CURRENTDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PARENTDIR = os.path.dirname(CURRENTDIR)
sys.path.insert(0, PARENTDIR)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()

from django.conf import settings
from flask import Flask, g, request

from factory.factory import ImplementationFactory
from utils import logger
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

Logger = logger.get_logger(__name__)


APP = Flask(__name__)
APP.register_blueprint(category_views)
APP.register_blueprint(defendant_views)
APP.register_blueprint(email_templates_views)
APP.register_blueprint(preset_views)
APP.register_blueprint(misc_views)
APP.register_blueprint(news_views)
APP.register_blueprint(provider_views)
APP.register_blueprint(report_views)
APP.register_blueprint(reputation_views)
APP.register_blueprint(tag_views)
APP.register_blueprint(ticket_views)
APP.register_blueprint(threshold_views)


@APP.before_request
def before_request():
    """
        Set start time
    """
    g.start = time.time()


@APP.after_request
def after_request(response):
    """
        Log all request
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
            path,
            http_code,
            diff,
        )
    return response


if __name__ == '__main__':

    APP.run(host=settings.API['host'], port=settings.API['port'])
