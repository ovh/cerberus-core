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

from flask import Blueprint, g, request

from api.controllers import PresetsController
from decorators import admin_required, jsonify

preset_views = Blueprint('preset_views', __name__)


@preset_views.route('/api/presets', methods=['GET'])
@jsonify
def get_all_presets():
    """
        Get all `abuse.models.TicketWorkflowPreset` available
    """
    filters = None
    if 'filters' in request.args:
        filters = request.args['filters']
    code, resp = PresetsController.index(g.user, filters=filters)
    return code, resp


@preset_views.route('/api/presets', methods=['POST'])
@jsonify
@admin_required
def create_preset():
    """
        Create a `abuse.models.TicketWorkflowPreset`
    """
    body = request.get_json()
    code, resp = PresetsController.create(g.user, body)
    return code, resp


@preset_views.route('/api/presets/<preset>', methods=['GET'])
@jsonify
def get_preset(preset=None):
    """
        Get given preset info
    """
    code, resp = PresetsController.show(g.user, preset)
    return code, resp


@preset_views.route('/api/presets/<preset>', methods=['PUT'])
@jsonify
@admin_required
def update_preset(preset=None):
    """
        Update given preset info
    """
    body = request.get_json()
    code, resp = PresetsController.update(g.user, preset, body)
    return code, resp


@preset_views.route('/api/presets/<preset>', methods=['DELETE'])
@jsonify
@admin_required
def delete_preset(preset=None):
    """
        Delete given preset info
    """
    code, resp = PresetsController.delete(g.user, preset)
    return code, resp


@preset_views.route('/api/presets/order', methods=['PUT'])
@jsonify
@admin_required
def order_presets():
    """
        Update preset order for display
    """
    body = request.get_json()
    code, resp = PresetsController.update_order(g.user, body)
    return code, resp
