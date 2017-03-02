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
    ReportThreshold views for Cerberus protected API.
"""

from flask import Blueprint, request

from api.controllers import ThresholdController
from decorators import admin_required, Cached, InvalidateCache

threshold_views = Blueprint('threshold_views', __name__)


@threshold_views.route('/api/admin/threshold', methods=['GET'])
@admin_required
@Cached(timeout=43200)
def get_all_threshold():
    """ Get all report's threshold
    """
    return ThresholdController.get_all()


@threshold_views.route('/api/admin/threshold/<threshold>', methods=['GET'])
@admin_required
def get_threshold(threshold=None):
    """ Get given threshold
    """
    return ThresholdController.show(threshold)


@threshold_views.route('/api/admin/threshold', methods=['POST'])
@admin_required
@InvalidateCache(routes=['/api/admin/threshold'])
def create_threshold():
    """ Post a new threshold
    """
    body = request.get_json()
    return ThresholdController.create(body)


@threshold_views.route('/api/admin/threshold/<threshold>', methods=['PUT'])
@admin_required
@InvalidateCache(routes=['/api/admin/threshold'])
def update_threshold(threshold=None):
    """ Update given threshold
    """
    body = request.get_json()
    return ThresholdController.update(threshold, body)


@threshold_views.route('/api/admin/threshold/<threshold>', methods=['DELETE'])
@admin_required
@InvalidateCache(routes=['/api/admin/threshold'])
def delete_threshold(threshold=None):
    """ Delete given threshold
    """
    return ThresholdController.destroy(threshold)
