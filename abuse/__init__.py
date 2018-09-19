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
    Init Cerberus App
"""

import os

from flask import Flask

from .api import CustomResponse, ExtendedRequest
from .config import env_config, load_config


class CerberusApp(Flask):

    response_class = CustomResponse
    request_class = ExtendedRequest
    _config = load_config(
        os.getenv("APP_SETTINGS", None), os.getenv("APP_ENV", "default")
    )


def create_app(environment="default"):
    """
        Initialize application
    """
    app = CerberusApp(__name__)

    # Load default vars for env
    app.config.from_object(env_config[environment])

    # Merge config with previously loaded one
    app.config.update(app._config)

    # Init app environment
    env_config[environment].init_app(app)

    return app
