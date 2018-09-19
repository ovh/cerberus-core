#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017, OVH SAS
#
# This file is part of Cerberus.
#
# Revmon is free software: you can redistribute it and/or modify
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
    Main for Cerberus
"""

import importlib
import os

import click

from flask.cli import FlaskGroup

import abuse.commands


def make_app(info):
    """
        Create Cerberus APP
    """
    from abuse import create_app

    return create_app(os.getenv("APP_ENV", "default"))


class UWSGIApp(object):

    app = None

    @classmethod
    def setup(cls):

        if not cls.app:
            cls.app = make_app(None)


def get_uwsgi_app(*args, **kwargs):

    UWSGIApp.setup()
    return UWSGIApp.app(*args, **kwargs)


@click.group(cls=FlaskGroup, create_app=make_app)
def app():
    """ Cerberus CLI """


# commands auto-discovery
#
for m in abuse.commands.__all__:
    module = importlib.import_module("abuse.commands.%s" % m)
    for func_name in dir(module):
        func = module.__dict__.get(func_name)
        if type(func) == click.core.Command:
            app.add_command(func)


if __name__ == "__main__":
    app()
