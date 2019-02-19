#
# Copyright (C) 2015-2019, OVH SAS
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
    Rules views for Cerberus protected API.
"""

from flask import Blueprint, request
from ..controllers import rules as RulesController
from ..decorators import admin_required

rules_views = Blueprint(
    'rules_views',
    __name__,
    url_prefix='/rules'
)

# /rules

@rules_views.route('', methods=['GET'])
def get_rules():
    """ Get abuse business rules """
    return RulesController.get_rules(filters=request.args.get('filters'))


@rules_views.route('', methods=['POST'])
@admin_required
def create_rule():
    """ Create a new business rule """
    body = request.get_json()
    return RulesController.create(body)

# /rules/<id>

@rules_views.route('/<rule>', methods=['GET'])
def get_rule(rule=None):
    """ Get specific business rule. """
    return RulesController.show(rule)


@rules_views.route('/<rule>', methods=['PUT'])
@admin_required
def update_rule(rule=None):
    """ Update given rule. """
    body = request.get_json()
    return RulesController.update(rule, body)


@rules_views.route('/<rule>', methods=['DELETE'])
@admin_required
def delete_rule(rule=None):
    """ Delete given business rule. """
    return RulesController.destroy(rule)

# /rules/conditions

@rules_views.route('/conditions', methods=['GET'])
def get_conditions():
    """ Get business rules conditions. """
    return RulesController.get_conditions()

# /rules/actions

@rules_views.route('/actions', methods=['GET'])
def get_actions():
    """ Get business rules actions. """
    return RulesController.get_actions()

# /rules/operators
@rules_views.route('/operators', methods=['GET'])
def get_operators():
    """ Get business rules operators. """
    return RulesController.get_operators()
