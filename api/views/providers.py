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
from decorators import admin_required

provider_views = Blueprint('provider_views', __name__)


@provider_views.route('/api/providers', methods=['GET'])
def get_providers():
    """ Get list of providers

        Filtering is possible through "filters" query string, JSON double encoded format
    """
    return ProvidersController.index(filters=request.args.get('filters'))


@provider_views.route('/api/providers', methods=['POST'])
@admin_required
def create_provider():
    """ Create a new provider
    """
    body = request.get_json()
    return ProvidersController.create(body)


@provider_views.route('/api/providers/<provider>', methods=['PUT', 'DELETE'])
@admin_required
def update_provider(provider=None):
    """ Update a given provider
    """
    if request.method == 'PUT':
        body = request.get_json()
        return ProvidersController.update(provider, body)
    else:
        return ProvidersController.destroy(provider)


@provider_views.route('/api/providers/<provider>/tags', methods=['POST'])
@admin_required
def add_provider_tag(provider=None):
    """ Add tag to provider
    """
    body = request.get_json()
    return ProvidersController.add_tag(provider, body)


@provider_views.route('/api/providers/<provider>/tags/<tag>', methods=['DELETE'])
@admin_required
def delete_provider_tag(provider=None, tag=None):
    """ Remove provider tag
    """
    return ProvidersController.remove_tag(provider, tag)
