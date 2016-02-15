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
    Provider views for Cerberus protected API.
"""

from flask import Blueprint, request

from api.controllers import ProvidersController
from decorators import (admin_required, catch_500, json_required, jsonify,
                        token_required)

provider_views = Blueprint('provider_views', __name__)


@provider_views.route('/api/providers', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_providers():
    """ Get list of providers

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    if 'filters' in request.args:
        code, resp = ProvidersController.index(filters=request.args['filters'])
    else:
        code, resp = ProvidersController.index()
    return code, resp


@provider_views.route('/api/providers', methods=['POST'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def create_provider():
    """ Create a new provider
    """
    body = request.get_json()
    code, resp = ProvidersController.create(body)
    return code, resp


@provider_views.route('/api/providers/<provider>', methods=['PUT', 'DELETE'])
@jsonify
@token_required
@admin_required
@catch_500
def update_provider(provider=None):
    """ Update a given provider
    """
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = ProvidersController.update(provider, body)
    else:
        code, resp = ProvidersController.destroy(provider)
    return code, resp


@provider_views.route('/api/providers/<provider>/tags', methods=['POST'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def add_provider_tag(provider=None):
    """ Add tag to provider
    """
    body = request.get_json()
    code, resp = ProvidersController.add_tag(provider, body)
    return code, resp


@provider_views.route('/api/providers/<provider>/tags/<tag>', methods=['DELETE'])
@jsonify
@token_required
@admin_required
@catch_500
def delete_provider_tag(provider=None, tag=None):
    """ Remove provider tag
    """
    code, resp = ProvidersController.remove_tag(provider, tag)
    return code, resp
