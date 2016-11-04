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
from decorators import Cached, perm_required


defendant_views = Blueprint('defendant_views', __name__)


@defendant_views.route('/api/defendants/top20', methods=['GET'])
@Cached(timeout=3600)
def get_defendant_top20():
    """ Get Abuse defendants top20
    """
    return DefendantsController.get_defendant_top20()


@defendant_views.route('/api/defendants/<defendant>', methods=['GET'])
def get_defendant(defendant=None):
    """ Get a defendant
    """
    return DefendantsController.show(defendant)


@defendant_views.route('/api/defendants/<defendant>/comments', methods=['POST'])
@perm_required
def add_comment(defendant=None):
    """ Add comment to defendant
    """
    body = request.get_json()
    return CommentsController.create(body, defendant_id=defendant, user_id=g.user.id)


@defendant_views.route('/api/defendants/<defendant>/services', methods=['GET'])
def get_defendant_services(defendant=None):
    """
        Get services for a given defendant
    """
    return DefendantsController.get_defendant_services(defendant)


@defendant_views.route('/api/defendants/<defendant>/comments/<comment>', methods=['PUT', 'DELETE'])
@perm_required
def update_or_delete_comment(defendant=None, comment=None):
    """ Update or delete defendant comments
    """
    if request.method == 'PUT':
        body = request.get_json()
        return CommentsController.update(
            body,
            comment_id=comment,
            user_id=g.user.id
        )
    else:
        return CommentsController.delete(
            comment_id=comment,
            defendant_id=defendant,
            user_id=g.user.id
        )


@defendant_views.route('/api/defendants/<defendant>/tags', methods=['POST'])
@perm_required
def add_defendant_tag(defendant=None):
    """ Add tag to defendant
    """
    body = request.get_json()
    return DefendantsController.add_tag(defendant, body, g.user)


@defendant_views.route('/api/defendants/<defendant>/tags/<tag>', methods=['DELETE'])
@perm_required
def delete_defendant_tag(defendant=None, tag=None):
    """ Remove defendant tag
    """
    return DefendantsController.remove_tag(defendant, tag, g.user)


@defendant_views.route('/api/stats/tickets/<defendant>', methods=['GET'])
def get_defendant_tickets_stats(defendant=None):
    """ Get tickets stats for a given defendant
    """
    return DefendantsController.get_defendant_stats(defendant=defendant, nature='tickets')


@defendant_views.route('/api/stats/reports/<defendant>', methods=['GET'])
def get_defendant_reports_stats(defendant=None):
    """
        Get reports stats for a given defendant
    """
    return DefendantsController.get_defendant_stats(defendant=defendant, nature='reports')
