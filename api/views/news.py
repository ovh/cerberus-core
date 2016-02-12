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
    News views for Cerberus protected API.
"""

from flask import Blueprint, request

from api.controllers import GeneralController, NewsController
from decorators import (admin_required, catch_500, json_required, jsonify,
                        token_required)

news_views = Blueprint('news_views', __name__)


@news_views.route('/api/news', methods=['GET'])
@catch_500
@jsonify
@token_required
def get_all_news():
    """ Get abuse news

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    if 'filters' in request.args:
        code, resp = NewsController.index(filters=request.args['filters'])
    else:
        code, resp = NewsController.index()
    return code, resp


@news_views.route('/api/news/<news>', methods=['GET'])
@catch_500
@jsonify
@token_required
def get_news(news=None):
    """ Get a given news
    """
    code, resp = NewsController.show(news)
    return code, resp


@news_views.route('/api/news', methods=['POST'])
@catch_500
@jsonify
@token_required
@json_required
def create_news():
    """ Post a news
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = NewsController.create(body, user)
    return code, resp


@news_views.route('/api/news/<news>', methods=['PUT'])
@catch_500
@jsonify
@token_required
@json_required
def update_news(news=None):
    """ Update a given new
    """
    user = GeneralController.get_user(request)
    body = request.get_json()
    code, resp = NewsController.update(news, body, user)
    return code, resp


@news_views.route('/api/news/<news>', methods=['DELETE'])
@catch_500
@jsonify
@token_required
@admin_required
def delete_news(news=None):
    """ Delete a given new
    """
    code, resp = NewsController.destroy(news)
    return code, resp
