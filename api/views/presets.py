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
from decorators import admin_required

preset_views = Blueprint('preset_views', __name__)


@preset_views.route('/api/presets', methods=['GET'])
def get_all_presets():
    """
        Get all `abuse.models.TicketWorkflowPreset` available
    """
    return PresetsController.index(g.user, filters=request.args.get('filters'))


@preset_views.route('/api/presets', methods=['POST'])
@admin_required
def create_preset():
    """
        Create a `abuse.models.TicketWorkflowPreset`
    """
    body = request.get_json()
    return PresetsController.create(g.user, body)


@preset_views.route('/api/presets/<preset>', methods=['GET'])
def get_preset(preset=None):
    """
        Get given preset info
    """
    return PresetsController.show(g.user, preset)


@preset_views.route('/api/presets/<preset>', methods=['PUT'])
@admin_required
def update_preset(preset=None):
    """
        Update given preset info
    """
    body = request.get_json()
    return PresetsController.update(g.user, preset, body)


@preset_views.route('/api/presets/<preset>', methods=['DELETE'])
@admin_required
def delete_preset(preset=None):
    """
        Delete given preset info
    """
    return PresetsController.delete(g.user, preset)


@preset_views.route('/api/presets/order', methods=['PUT'])
@admin_required
def order_presets():
    """
        Update preset order for display
    """
    body = request.get_json()
    return PresetsController.update_order(g.user, body)
