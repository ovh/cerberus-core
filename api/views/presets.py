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
    Preset views for Cerberus protected API.
"""

from flask import Blueprint, request

from api.controllers import GeneralController, PresetsController
from decorators import (admin_required, catch_500, json_required, jsonify,
                        token_required)

preset_views = Blueprint('preset_views', __name__)


@preset_views.route('/api/presets', methods=['GET'])
@catch_500
@jsonify
@token_required
def get_all_presets():
    """
        Get all `abuse.models.TicketWorkflowPreset` available
    """
    filters = None
    if 'filters' in request.args:
        filters = request.args['filters']
    user = GeneralController.get_user(request)
    code, resp = PresetsController.index(user, filters=filters)
    return code, resp


@preset_views.route('/api/presets', methods=['POST'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def create_preset():
    """
        Create a `abuse.models.TicketWorkflowPreset`
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    code, resp = PresetsController.create(user, body)
    return code, resp


@preset_views.route('/api/presets/<preset>', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_preset(preset=None):
    """
        Get given preset info
    """
    user = GeneralController.get_user(request)
    code, resp = PresetsController.show(user, preset)
    return code, resp


@preset_views.route('/api/presets/<preset>', methods=['PUT'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def update_preset(preset=None):
    """
        Update given preset info
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    code, resp = PresetsController.update(user, preset, body)
    return code, resp


@preset_views.route('/api/presets/<preset>', methods=['DELETE'])
@jsonify
@token_required
@admin_required
@catch_500
def delete_preset(preset=None):
    """
        Delete given preset info
    """
    user = GeneralController.get_user(request)
    code, resp = PresetsController.delete(user, preset)
    return code, resp


@preset_views.route('/api/presets/order', methods=['PUT'])
@jsonify
@token_required
@admin_required
@json_required
@catch_500
def order_presets():
    """
        Update preset order for display
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    code, resp = PresetsController.update_order(user, body)
    return code, resp
