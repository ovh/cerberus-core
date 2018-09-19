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
import sys

import click
import yaml

from django.core.management import call_command

from .. import create_app


@click.command("test", short_help="Runs tests.")
@click.option("--settings")
@click.option("--pattern")
def run_tests(settings, pattern):

    config_file = (
        settings or os.getenv("APP_SETTINGS") or "abuse/tests/settings-test.yml"
    )
    config = read_config(config_file)
    pattern = pattern or "test*.py"

    try:
        if (
            not config["DJANGO"]["DEBUG"]
            or not config["DJANGO"]["DATABASES"]["default"].get("TEST")
            or not os.getenv("APP_ENV") == "test"
        ):
            print('\n/!\ Invalid tests settings "{}"\n'.format(config_file))
            sys.exit(1)
    except KeyError:
        print('\n/!\ Invalid test settings "{}"\n'.format(config_file))
        sys.exit(1)

    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(**config["DJANGO"])
        django.setup()

    call_command(
        *("migrate", "--run-syncdb"), verbosity=0, interactive=False, out="/dev/null"
    )

    app = create_app(environment="test")

    with app.app_context():
        call_command("test", "abuse.tests", "--pattern", pattern, interactive=False)


def read_config(config_file):
    # Locate the config file to use
    if not os.path.isfile(config_file):
        print("Missing configuration file")
        return {}

    # Open and read the config file
    with codecs.open(config_file, "r", "utf8") as file_handler:
        conf = yaml.load(file_handler)
    if conf is None:
        conf = {}
    return conf
