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

from flask import Blueprint, g, request

from api.controllers import CommentsController, DefendantsController
from decorators import Cached, jsonify, perm_required


defendant_views = Blueprint('defendant_views', __name__)


@defendant_views.route('/api/defendants/top20', methods=['GET'])
@jsonify
@Cached(timeout=3600)
def get_defendant_top20():
    """ Get Abuse defendants top20
    """
    code, resp = DefendantsController.get_defendant_top20()
    return code, resp


@defendant_views.route('/api/defendants/<defendant>', methods=['GET'])
@jsonify
def get_defendant(defendant=None):
    """ Get a defendant
    """
    code, resp = DefendantsController.show(defendant)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/comments', methods=['POST'])
@jsonify
@perm_required
def add_comment(defendant=None):
    """ Add comment to defendant
    """
    body = request.get_json()
    code, resp = CommentsController.create(body, defendant_id=defendant, user_id=g.user.id)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/services', methods=['GET'])
@jsonify
def get_defendant_services(defendant=None):
    """
        Get services for a given defendant
    """
    code, resp = DefendantsController.get_defendant_services(defendant)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/comments/<comment>', methods=['PUT', 'DELETE'])
@jsonify
@perm_required
def update_or_delete_comment(defendant=None, comment=None):
    """ Update or delete defendant comments
    """
    if request.method == 'PUT':
        body = request.get_json()
        code, resp = CommentsController.update(body, comment_id=comment, user_id=g.user.id)
    else:
        code, resp = CommentsController.delete(comment_id=comment, defendant_id=defendant, user_id=g.user.id)

    return code, resp


@defendant_views.route('/api/defendants/<defendant>/tags', methods=['POST'])
@jsonify
@perm_required
def add_defendant_tag(defendant=None):
    """ Add tag to defendant
    """
    body = request.get_json()
    code, resp = DefendantsController.add_tag(defendant, body, g.user)
    return code, resp


@defendant_views.route('/api/defendants/<defendant>/tags/<tag>', methods=['DELETE'])
@jsonify
@perm_required
def delete_defendant_tag(defendant=None, tag=None):
    """ Remove defendant tag
    """
    code, resp = DefendantsController.remove_tag(defendant, tag, g.user)
    return code, resp


@defendant_views.route('/api/stats/tickets/<defendant>', methods=['GET'])
@jsonify
def get_defendant_tickets_stats(defendant=None):
    """ Get tickets stats for a given defendant
    """
    code, resp = DefendantsController.get_defendant_stats(defendant=defendant, nature='tickets')
    return code, resp


@defendant_views.route('/api/stats/reports/<defendant>', methods=['GET'])
@jsonify
def get_defendant_reports_stats(defendant=None):
    """
        Get reports stats for a given defendant
    """
    code, resp = DefendantsController.get_defendant_stats(defendant=defendant, nature='reports')
    return code, resp
