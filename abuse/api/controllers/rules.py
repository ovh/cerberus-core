# -*- coding: utf-8 -*-
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
    Cerberus rules controller
"""

import json
from urllib import unquote
from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import ObjectDoesNotExist
from django.forms.models import model_to_dict
from werkzeug.exceptions import BadRequest, NotFound
from abuse.models import BusinessRules
from abuse.rules import get_business_rules_variables, get_business_rules_actions, verify_rule
from abuse.rules.engine.operators import (BooleanType, NumericType, SelectMultipleType,
                                          SelectType, StringType)

def get_rules(**kwargs):
    """ Get business rules. """

    # Get filters
    filters = {}
    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex))

    # Set pagination
    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    # Set order
    sort = []
    try:
        sort += ['-' + k if v < 0 else k for k, v in filters['sortBy'].iteritems()]
    except KeyError:
        sort += ['id']

    # Set query fields
    fields = []
    if 'queryFields' in filters:
        # Query field on config does not make sense
        # Config is management by conditions/actions
        # Prevent the user to do it
        fields = filters['queryFields']
        for elt in fields:
            if elt not in ['id', 'name', 'rulesType', 'orderId', 'isActive']:
                raise BadRequest('Query field ' + elt + ' is not well-formed.')

    # DB query
    try:
        if fields:
            rules = BusinessRules.all().values(*fields).distinct().order_by(*sort)
        else:
            rules = BusinessRules.all().order_by(*sort)
        nb_rules_filtered = rules.count()
        rules = rules[(offset - 1) * limit:limit * offset]
    except (AttributeError, KeyError, FieldError,
            SyntaxError, TypeError, ValueError) as err:
        raise BadRequest(str(err))

    # Construct response
    if fields:
        response_rules = list(rules)
    else:
        response_rules = [_generate_business_rule(rule) for rule in rules]
    api_response = {}
    api_response['total'] = nb_rules_filtered
    api_response['rules'] = response_rules
    return api_response


def show(rule_id):
    """ Get details of specific rule. """
    try:
        rule = BusinessRules.get(id=rule_id)
    except (IndexError, ValueError):
        return BadRequest('Not a valid rules id')
    except ObjectDoesNotExist:
        return NotFound("Business rule does not exist.")
    business_rule = _generate_business_rule(rule)
    return business_rule


def create(rule):
    """ Create new rules. """
    # Check body
    try:
        verify_rule(rule)
    except (KeyError, ValueError) as error:
        return BadRequest(error)
    # Launch request
    try:
        # Get last orderId
        next_order_id = BusinessRules.objects.latest('orderId').orderId + 1
        rule["orderId"] = next_order_id
        # Create the business rule
        rule, _ = BusinessRules.get_or_create(**rule)
    except (FieldError, IntegrityError):
        raise BadRequest('Invalid fields in integrity of body')
    business_rule = _generate_business_rule(rule)
    return business_rule


def update(rule_id, body):
    """ Update business rule. """
    # Check body
    try:
        verify_rule(body)
    except (KeyError, ValueError) as error:
        return BadRequest(error)
    # Launch update
    try:
        rules = BusinessRules.get(id=rule_id)
    except (ObjectDoesNotExist, ValueError):
        return NotFound('Rules not found')
    try:
        # Update data in a row
        _reload_rules_order(body, rule_id)
        # Update data in DB
        BusinessRules.filter(pk=rules.pk).update(**body)
        rules = BusinessRules.get(pk=rules.pk)
    except (KeyError, FieldError, IntegrityError):
        raise BadRequest('Invalid fields in body')
    business_rule = _generate_business_rule(rules)
    return business_rule


def destroy(rules_id):
    """ Remove specific rule. """
    try:
        rules = BusinessRules.get(id=rules_id)
    except (ObjectDoesNotExist, ValueError):
        return NotFound('BusinessRules not found')
    rules.delete()
    return {'message': 'BusinessRules successfully removed'}


def get_conditions():
    """ Get Business Rules config conditions. """
    return get_business_rules_variables()


def get_actions():
    """ Get Business Rules config conditions. """
    return get_business_rules_actions()


def get_operators():
    """ Get operators of conditions. """
    return (BooleanType.get_all_operators()
            + NumericType.get_all_operators()
            + SelectMultipleType.get_all_operators()
            + SelectType.get_all_operators()
            + StringType.get_all_operators())


def _generate_business_rule(rule):
    """ Genereta JSON rule response. """
    business_rule = model_to_dict(rule)
    business_rule['config'] = rule.config
    return business_rule


def _reload_rules_order(rule_body, rule_id):
    """ Update order ID in db when data is updated.

     We do it if PUT method is done with orderId already presents in DB.
     In this case, the orders of priorities have to be updated.
     To do it, we increment order id of other data in update_order method.
    """
    # Init method
    altered_order_id = rule_body["orderId"]
    rule_type = rule_body["rulesType"]
    # Update db
    while True:
        db_result = _update_order_id(altered_order_id, rule_type, rule_id)
        if db_result is None:
            break
        altered_order_id = db_result[0]
        rule_id = db_result[1]


def _update_order_id(order_id, rule_type, data_id):
    """ Update order id of data if needed. """
    rules = BusinessRules.filter(orderId=order_id, rulesType=rule_type).exclude(id=data_id)
    # Check if data is unic
    if len(rules) > 1:
        raise BadRequest('Invalid body, duplicata foud in db')
    # DB query does not return any result, it means that db is up-to-date
    if not rules:
        return None
    # Rule in DB must be updated
    rule = rules[0]
    new_order_id = order_id + 1
    alter_body = {"orderId": new_order_id}
    BusinessRules.filter(pk=rule.pk).update(**alter_body)
    data_id = rule.id
    # Change next data
    return new_order_id, data_id
