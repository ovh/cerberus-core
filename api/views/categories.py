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
    Category views for Cerberus protected API.
"""

from flask import Blueprint, g, request
from voluptuous import Optional

from api.controllers import CategoriesController
from decorators import (admin_required, Cached, InvalidateCache,
                        validate_body)

category_views = Blueprint('category_views', __name__)


@category_views.route('/api/categories', methods=['GET'])
@Cached(timeout=43200)
def get_all_categories():
    """
    Returns all Cerberus categories

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Vary: Accept
       Content-Type: application/json

       [
        {
            "description": "Illegal",
            "name": "Illegal",
            "label": "Illegal"
        },
        {
            "description": "Copyright",
            "name": "Copyright",
            "label": "Copyright"
        }
       ]
    """
    return CategoriesController.index()


@category_views.route('/api/categories/<category>', methods=['GET'])
def get_category(category=None):
    """
    Returns the description of given `category`

    **Example request**:

    .. sourcecode:: http

       GET /api/categories/Illegal HTTP/1.1

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Vary: Accept
       Content-Type: application/json

       {
            "description": "Illegal",
            "name": "Illegal",
            "label": "Illegal"
       }

    :status 404: category not found
    """
    return CategoriesController.show(category)


@category_views.route('/api/categories', methods=['POST'])
@admin_required
@InvalidateCache(routes=['/api/categories'])
@validate_body({
    'description': unicode,
    'name': unicode,
    'label': unicode
})
def create_category():
    """
    Create a new category

    :reqjson str description: The description of the new category
    :reqjson str name: The name of the new category
    :reqjson str label: The label of the new category

    :status 201: when category is successfully created
    :status 400: when parameters are missing or invalid
    """
    body = request.get_json()
    return CategoriesController.create(body)


@category_views.route('/api/categories/<category>', methods=['PUT'])
@admin_required
@InvalidateCache(routes=['/api/categories'])
@validate_body({
    'description': unicode,
    Optional('name'): unicode,
    'label': unicode
})
def update_category(category=None):
    """
    Update given `category`

    **Example request**:

    .. sourcecode:: http

       PUT /api/categories/Illegal HTTP/1.1
       Content-Type: application/json

       {
           "description": "Test",
           "name": "Illegal",
           "label": "Test"
       }

    :reqjson str description: The description of the category
    :reqjson str name: The name of the category
    :reqjson str label: The label of the category

    :status 200: when no error
    :status 400: when parameters are missing or invalid
    :status 404: when the given `category` was not found
    """
    body = request.get_json()
    return CategoriesController.update(category, body)


@category_views.route('/api/categories/<category>', methods=['DELETE'])
@admin_required
@InvalidateCache(routes=['/api/categories'])
def delete_category(category=None):
    """
    Delete given `category`

    **Example request**:

    .. sourcecode:: http

       DELETE /api/categories/Illegal HTTP/1.1

    :status 200: when no error
    :status 403: when `category` is still referenced by a ticket/report
    :status 404: when the given `category` was not found
    """
    return CategoriesController.destroy(category)


@category_views.route('/api/my-categories', methods=['GET'])
def get_user_categories():
    """
    Get allowed categories for logged user

    **Example request**:

    .. sourcecode:: http

       GET /api/my-categories HTTP/1.1

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Vary: Accept
       Content-Type: application/json

       [
        {
            "description": "Illegal",
            "name": "Illegal",
            "label": "Illegal"
        },
       ]

    :status 404: category not found

    """
    return CategoriesController.index(user=g.user)
