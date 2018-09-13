# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2017, OVH SAS
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
    Decorators for Cerberus API.
"""

from functools import wraps

from flask import g, request
from voluptuous import Invalid, MultipleInvalid, Schema
from werkzeug.exceptions import BadRequest, Forbidden

from .controllers import misc as MiscController

Schemas = {}


def admin_required(func):
    """ Check if user is admin
    """
    @wraps(func)
    def check_admin(*args, **kwargs):
        if not g.user.operator.role.codename == 'admin':
            raise Forbidden('Forbidden')
        return func(*args, **kwargs)
    return check_admin


def perm_required(func):
    """ Check if user can do actions
    """
    @wraps(func)
    def check_perm(*args, **kwargs):
        if 'report' in kwargs:
            MiscController.check_perms(
                method=request.method,
                user=g.user,
                report=kwargs['report']
            )
        if 'ticket' in kwargs:
            MiscController.check_perms(
                method=request.method,
                user=g.user,
                ticket=kwargs['ticket']
            )
        if 'defendant' in kwargs and request.method != 'GET':
            MiscController.check_perms(
                method=request.method,
                user=g.user,
                defendant=kwargs['defendant']
            )
        return func(*args, **kwargs)
    return check_perm


def validate_body(schema_desc):
    """
        Validate json body
    """
    def real_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                body = request.get_json()
                if not Schemas.get(func.__name__):
                    Schemas[func.__name__] = Schema(schema_desc, required=True)
                Schemas[func.__name__](body)
            except (Invalid, MultipleInvalid):
                msg = 'Missing or invalid field(s) in body'
                raise BadRequest(msg)
            return func(*args, **kwargs)
        return wrapper
    return real_decorator
