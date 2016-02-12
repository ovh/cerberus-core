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
    Reputation views for Cerberus protected API.
"""

from flask import Blueprint, request

from api.controllers import ReputationController
from decorators import catch_500, jsonify, token_required

reputation_views = Blueprint('reputation_views', __name__)


@reputation_views.route('/api/reputation/ip/<ip_addr>/rbl', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_ip_rbl_reputation(ip_addr=None):
    """ Get live rbl reputation for ip
    """
    code, resp = ReputationController.get_ip_rbl_reputation(ip_addr)
    return code, resp


@reputation_views.route('/api/reputation/ip/<ip_addr>/internal', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_ip_internal_reputation(ip_addr=None):
    """ Get live internal reputation for ip
    """
    code, resp = ReputationController.get_ip_internal_reputation(ip_addr)
    return code, resp


@reputation_views.route('/api/reputation/ip/<ip_addr>/external', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_ip_external_reputation(ip_addr=None):
    """ Get live external reputation for ip
    """
    code, resp = ReputationController.get_ip_external_reputation(ip_addr)
    return code, resp


@reputation_views.route('/api/reputation/url/external', methods=['POST'])
@jsonify
@token_required
@catch_500
def get_url_external_reputation():
    """ Get live external reputation for url
    """
    body = request.get_json()
    if not body or not body.get('url'):
        resp = {'status': 'Bad Request', 'code': 400, 'message': 'Url field not found in body'}
        return 400, resp

    code, resp = ReputationController.get_url_external_reputation(body['url'])
    return code, resp


@reputation_views.route('/api/reputation/ip/<ip_addr>/external/<source>', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_ip_external_detail(ip_addr=None, source=None):
    """ Get detail for external reputation
    """
    code, resp = ReputationController.get_ip_external_detail(ip_addr, source)
    return code, resp


@reputation_views.route('/api/reputation/ip/<ip_addr>/tool', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_ip_tool(ip_addr=None):
    """ Get tool
    """
    code, resp = ReputationController.get_ip_tools(ip_addr)
    return code, resp
