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
    Tests for Cerberus
"""

import codecs
import os

import click
import yaml

from django.core.management import call_command

from .. import create_app


@click.command('initdb', short_help='Init Cerberus database.')
@click.option('--settings')
def initdb(settings):

    config_file = settings or os.getenv('APP_SETTINGS')
    environment = os.getenv('APP_ENV', 'dev')

    config = read_config(config_file)

    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(**config['DJANGO'])
        django.setup()

    call_command(
        *('migrate', '--run-syncdb'), verbosity=0,
        interactive=False, out='/dev/null'
    )

    call_command(*('loaddata', 'abuse/tests/fixtures.yaml'))

    create_app(environment=environment)


def read_config(config_file):
    # Locate the config file to use
    if not os.path.isfile(config_file):
        print('Missing configuration file')
        return {}

    # Open and read the config file
    with codecs.open(config_file, 'r', 'utf8') as file_handler:
        conf = yaml.load(file_handler)
    if conf is None:
        conf = {}
    return conf
