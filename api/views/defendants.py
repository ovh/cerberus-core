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
    Defendant views for Cerberus protected API.
"""

from flask import Blueprint, request

from api.controllers import (CommentsController, DefendantsController,
                             GeneralController)
from decorators import (catch_500, json_required, jsonify, perm_required,
                        token_required)


defendant_views = Blueprint('defendant_views', __name__)


@defendant_views.route('/api/defendants/top20', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_defendant_top20():
    """ Get Abuse defendants top20
    """
    code, resp = DefendantsController.get_defendant_top20()
    return code, resp


@defendant_views.route('/api/defendants/<defendant>', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_defendant(defendant=None):
    """ Get a defendant
    """
    code, resp = DefendantsController.show(defendant)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/comments', methods=['POST'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def add_comment(defendant=None):
    """ Add comment to defendant
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    code, resp = CommentsController.create(body, defendant_id=defendant, user_id=user.id)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/services', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_defendant_services(defendant=None):
    """
        Get services for a given defendant
    """
    code, resp = DefendantsController.get_defendant_services(defendant)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/comments/<comment>', methods=['PUT', 'DELETE'])
@jsonify
@token_required
@perm_required
@catch_500
def update_or_delete_comment(defendant=None, comment=None):
    """ Update or delete defendant comments
    """
    user = GeneralController.get_user(request)
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = CommentsController.update(body, comment_id=comment, user_id=user.id)
    else:
        code, resp = CommentsController.delete(comment_id=comment, defendant_id=defendant, user_id=user.id)

    return code, resp


@defendant_views.route('/api/defendants/<defendant>/tags', methods=['POST'])
@jsonify
@token_required
@perm_required
@json_required
@catch_500
def add_defendant_tag(defendant=None):
    """ Add tag to defendant
    """
    body = request.get_json()
    user = GeneralController.get_user(request)
    code, resp = DefendantsController.add_tag(defendant, body, user)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/tags/<tag>', methods=['DELETE'])
@jsonify
@token_required
@perm_required
@catch_500
def delete_defendant_tag(defendant=None, tag=None):
    """ Remove defendant tag
    """
    user = GeneralController.get_user(request)
    code, resp = DefendantsController.remove_tag(defendant, tag, user)
    return code, resp


@defendant_views.route('/api/stats/tickets/<defendant>', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_defendant_tickets_stats(defendant=None):
    """ Get tickets stats for a given defendant
    """
    code, resp = DefendantsController.get_defendant_stats(defendant=defendant, nature='tickets')
    return code, resp


@defendant_views.route('/api/stats/reports/<defendant>', methods=['GET'])
@jsonify
@token_required
@catch_500
def get_defendant_reports_stats(defendant=None):
    """
        Get reports stats for a given defendant
    """
    code, resp = DefendantsController.get_defendant_stats(defendant=defendant, nature='reports')
    return code, resp
