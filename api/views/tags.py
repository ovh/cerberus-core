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
    Tag views for Cerberus protected API.
"""

from flask import Blueprint, request

from api.controllers import TagsController
from decorators import (admin_required, catch_500, json_required, jsonify,
                        token_required)

tag_views = Blueprint('tag_views', __name__)


@tag_views.route('/api/tags', methods=['GET'])
@catch_500
@jsonify
@token_required
def get_all_tags():
    """ Returns all abuse tags
    """
    if 'tagType' in request.args:
        code, resp = TagsController.index(tagType=request.args['tagType'])
    else:
        code, resp = TagsController.index()
    return code, resp


@tag_views.route('/api/tags/types', methods=['GET'])
@catch_500
@jsonify
@token_required
def get_tag_type():
    """ Get status list for ticket or report
    """
    return 200, TagsController.get_tag_type()


@tag_views.route('/api/tags/<tag>', methods=['GET'])
@catch_500
@jsonify
@token_required
def get_tag(tag=None):
    """ Return infos for a given tag
    """
    code, resp = TagsController.show(tag)
    return code, resp


@tag_views.route('/api/tags', methods=['POST'])
@catch_500
@jsonify
@token_required
@admin_required
@json_required
def create_tag():
    """ Create a new tags
    """
    body = request.get_json()
    code, resp = TagsController.create(body)
    return code, resp


@tag_views.route('/api/tags/<tag>', methods=['PUT'])
@catch_500
@jsonify
@token_required
@admin_required
@json_required
def update_tag(tag=None):
    """ Update an existing tag
    """
    body = request.get_json()
    code, resp = TagsController.update(tag, body)
    return code, resp


@tag_views.route('/api/tags/<tag>', methods=['DELETE'])
@catch_500
@jsonify
@token_required
@admin_required
def delete_tag(tag=None):
    """ Delete a given tag
    """
    code, resp = TagsController.destroy(tag)
    return code, resp
