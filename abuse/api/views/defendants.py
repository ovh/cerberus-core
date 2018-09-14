# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017, OVH SAS
#
# This file is part of Cerberus.
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

from ..cache import Cache
from ..decorators import perm_required
from ..controllers import comments as CommentsController
from ..controllers import defendants as DefendantsController


defendant_views = Blueprint(
    'defendant_views',
    __name__,
    url_prefix='/defendants'
)


@defendant_views.route('/top20', methods=['GET'])
@Cache.cached(timeout=3600)
def get_defendant_top20():
    """ Get Abuse defendants top20
    """
    return DefendantsController.get_defendant_top20()


@defendant_views.route('/<defendant>', methods=['GET'])
def get_defendant(defendant=None):
    """ Get a defendant
    """
    return DefendantsController.show(defendant)


@defendant_views.route('/<defendant>/comments', methods=['POST'])
@perm_required
def add_comment(defendant=None):
    """ Add comment to defendant
    """
    body = request.get_json()
    return CommentsController.create(
        body,
        defendant_id=defendant,
        user_id=g.user.id
    )


@defendant_views.route('/<defendant>/services', methods=['GET'])
def get_defendant_services(defendant=None):
    """
        Get services for a given defendant
    """
    return DefendantsController.get_defendant_services(defendant)


@defendant_views.route(
    '/<defendant>/comments/<comment>',
    methods=['PUT', 'DELETE']
)
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

    return CommentsController.delete(
        comment_id=comment,
        defendant_id=defendant,
        user_id=g.user.id
    )


@defendant_views.route('/<defendant>/tags', methods=['POST'])
@perm_required
def add_defendant_tag(defendant=None):
    """ Add tag to defendant
    """
    body = request.get_json()
    return DefendantsController.add_tag(defendant, body, g.user)


@defendant_views.route('/<defendant>/tags/<tag>', methods=['DELETE'])
@perm_required
def delete_defendant_tag(defendant=None, tag=None):
    """ Remove defendant tag
    """
    return DefendantsController.remove_tag(defendant, tag, g.user)
