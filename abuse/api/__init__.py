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

import json
import re

from datetime import datetime
from time import mktime

from flask import Response
from flask.wrappers import Request


class CustomResponse(Response):  # pylint: disable=too-many-ancestors
    """
        This class wraps FlasK/Werkzeug Response to handle Json
    """
    @classmethod
    def force_type(cls, rv, environ=None):
        if isinstance(rv, (dict, list)):
            rv = Response(
                json.dumps(cls._format_response(rv)),
                content_type='application/json'
            )
        return super(CustomResponse, cls).force_type(rv, environ)

    @classmethod
    def _format_response(cls, obj):
        """
            Convert a snake_cased obj to a camelCase one

            :param obj obj: The obj to convert
            :rtype: obj
            :returns: the converted obj
        """
        if isinstance(obj, dict):
            new_dict = {}

            for key, value in obj.iteritems():
                if isinstance(value, dict):
                    value = cls._format_response(value)

                elif isinstance(value, list):
                    value = [cls._format_response(i) for i in value]

                elif isinstance(value, datetime):
                    value = int(mktime(value.timetuple()))

                new_key_name = cls._to_camel_case(key)
                new_dict[new_key_name] = value

            return new_dict

        if isinstance(obj, list):
            return [cls._format_response(i) for i in obj]

        if isinstance(obj, datetime):
            return int(mktime(obj.timetuple()))

        return obj

    @classmethod
    def _to_camel_case(cls, string):
        """Give the camelCase representation of a snake_case string."""
        return re.sub(r'_(\w)', lambda x: x.group(1).upper(), string)


class ExtendedRequest(Request):
    @property
    def json(self):
        return self.get_json(force=True)
