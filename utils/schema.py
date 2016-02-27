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
    Voluptuous Schema for Adapters
"""

from voluptuous import Invalid, MultipleInvalid, Schema

from adapters.dao.customer.abstract import DefendantClass, ServiceClass


Schemas = {
    'CustomerDaoBase': {
        'get_services_from_items': Schema([
            {
                'defendant': DefendantClass,
                'service': ServiceClass,
                'items': {
                    'ips': set,
                    'urls': set,
                    'fqdn': set,
                },
            }
        ], required=True),
        'get_customer_infos': Schema(DefendantClass, required=True),
        'get_service_infos': Schema(ServiceClass, required=True),
        'get_customer_services': Schema([
            {
                'zone': str,
                'services': [ServiceClass],
            }
        ], required=True)
    },
}


class InvalidFormatError(Exception):
    """ Exception raised when schema is not respected

        .. py:class:: InvalidFormatError
    """
    def __init__(self, message):
        super(InvalidFormatError, self).__init__(message)


class SchemaNotFound(Exception):
    """ Exception raised when schema is not found

        .. py:class:: SchemaNotFound
    """
    def __init__(self, message):
        super(SchemaNotFound, self).__init__(message)


def valid_adapter_response(base_name, func_name, data):
    """
        Valid that given data match described schema

        :param str base_name: The name of the asbtract
        :param str func_name: The name of the called function
        :parma raw data: The data to valid
        :raises InvalidFormatError: if data is not compliant
    """
    if not data:
        return
    try:
        Schemas[base_name][func_name](data)
    except (KeyError, TypeError, ValueError):
        raise SchemaNotFound('Schema not found for %s.%s' % (base_name, func_name))
    except (Invalid, MultipleInvalid):
        raise InvalidFormatError('Given data is not compliant to %s.%s schema' % (base_name, func_name))
