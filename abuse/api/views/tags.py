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

from ..cache import Cache
from ..decorators import admin_required
from ..controllers import tags as TagsController

tag_views = Blueprint(
    'tag_views',
    __name__,
    url_prefix='/tags'
)


@tag_views.route('', methods=['GET'])
@Cache.cached(timeout=43200)
def get_all_tags():
    """ Returns all abuse tags
    """
    if 'tagType' in request.args:
        return TagsController.get_tags(tagType=request.args['tagType'])
    return TagsController.get_tags()


@tag_views.route('/types', methods=['GET'])
@Cache.cached(timeout=43200)
def get_tag_type():
    """ Get status list for ticket or report
    """
    return TagsController.get_tag_type()


@tag_views.route('/<tag>', methods=['GET'])
def get_tag(tag=None):
    """ Return infos for a given tag
    """
    return TagsController.show(tag)


@tag_views.route('', methods=['POST'])
@admin_required
@Cache.invalidate(routes=['/api/tags'])
def create_tag():
    """ Create a new tags
    """
    body = request.get_json()
    return TagsController.create(body)


@tag_views.route('/<tag>', methods=['PUT'])
@admin_required
@Cache.invalidate(routes=['/api/tags'])
def update_tag(tag=None):
    """ Update an existing tag
    """
    body = request.get_json()
    return TagsController.update(tag, body)


@tag_views.route('/<tag>', methods=['DELETE'])
@admin_required
@Cache.invalidate(routes=['/api/tags'])
def delete_tag(tag=None):
    """ Delete a given tag
    """
    return TagsController.destroy(tag)
