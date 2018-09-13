#!/usr/bin/env python
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
    Add or update Cerberus business rules
"""

import sys

import click
import yaml

from flask.cli import with_appcontext

from ..models import BusinessRules
from ..rules import verify_rule


@click.command('add-rule', short_help='Add or update a Cerberus rule from file.')
@click.option('rule_location', '--rule')
@with_appcontext
def update_rule(rule_location):

    rule = get_rule(rule_location)
    if not rule:
        click.echo('[update-rule] Error while fetching rule "{}"'.format(rule_location))
        sys.exit(1)

    name, rules_type = rule['name'], rule['rulesType']

    click.confirm(
        'You are about to add/update rule "{}" of type "{}"\nContinue?'.format(name, rules_type),
        abort=True
    )

    br = BusinessRules.filter(name=name, rulesType=rules_type).last()
    if br:
        br.orderId = rule['orderId']
        br.config = rule['config']
        br.save()
    else:
        BusinessRules.create(**rule)

    click.echo('[update-rule] Rule updated')


def get_rule(rule_location):

    with open(rule_location) as fd:
        try:
            rule = yaml.load(fd.read())
        except yaml.parser.ParserError:
            click.echo('[update-rule] Malformed yaml file')
            return

    if not all([rule.get(k) for k in ('config', 'name', 'orderId', 'rulesType')]):
        click.echo('[update-rule] Missing keys in rule')
        return

    verify_rule(rule)

    return rule
