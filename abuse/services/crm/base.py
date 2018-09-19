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
    Defines Customer DAO abstract Class and related Defendant/Service class
"""

import abc
import inspect

from datetime import datetime
from time import mktime

from ...models import Service
from ...models.defendant import DefendantRevision


class CRMServiceException(Exception):
    """ Exception that must be raised by CRMService implementations
        to ensure error are correctly handled.

        .. py:class:: CRMServiceException
    """

    def __init__(self, message):
        super(CRMServiceException, self).__init__(message)


class CRMServiceBase(object):
    """
        Service that interact with your CRM, RDBMS, or API.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_services_from_items(self, ips=None, urls=None, fqdn=None):
        """
            Map service/defendant for given items (provided by cerberus parser)

            :param list ips: List of IP address.
            :param list urls: List of URLs.
            :param list fqdn: List of fqdn
            :return: The result of the parsing of given items
            :rtype: dict
            :raises `cerberus.services.crm.base.CRMServiceException`: if error

            Do the magic with your own implementation,
            but cerberus parser is expecting this kind of struct

            [
                {
                    'service': ServiceClass(),
                    'defendant': 'DefendantClass(),
                    'items': {
                        'ips': set(['1.1.1.1']),
                        'urls': None,
                        'fqdn': None,
                    },
                },
                {
                    'service': ServiceClass(),
                    'defendant': 'DefendantClass(),
                    'items': {
                        'ips': None,
                        'urls': set(['https://www.example.com/phishing']),
                        'fqdn': None,
                    },
                },
                ...
            ]

            or [] if nothing match.

            Ex:
                get_services_from_items(
                    ips=['1.1.1.1','2.2.2.2'],
                    urls=['https://2.2.2.2/phishing.html']
                )

                returns:

                [
                    {
                        'service': {
                            'serviceId': '67891234',
                            'name' 'vps123456',
                            'domain': 'vps123456.provider.com',
                            'componentType': 'VPS',
                            'componentSubType': 'KVM',
                            'reference': 'vps.pro.2016',
                        },
                        'defendant': {,
                            'email': 'mr.robot@example.com',
                            'spareEmail': 'backup@domain.tld',
                            'customerId': 'mr.robot.A46Z',  # uuid in CRM
                            ...
                        },
                        'items': {
                            'ips': set(['2.2.2.2']),
                            'urls': set(['https://2.2.2.2/phishing.html']),
                            'fqdn': None,
                        },
                    },
                    {
                        'service': {
                            'serviceId': '123456',
                            'name' 'example',
                            'domain': 'www.example.com',
                            'componentType': 'DEDICATED',
                            'componentSubType': None,
                            'reference': 'dedicated.pro.2016',
                        },
                        'defendant': {,
                            'email': 'john.doe@example.com',
                            'spareEmail': 'backup@domain.tld',
                            'customerId': 'john.doe.123456',  # uuid in CRM
                            ...
                        },
                        'items': {
                            'ips': set(['1.1.1.1']),
                            'urls': None,
                            'fqdn': None,
                        },
                    },
                ]
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_customer_infos(self, customer_id):
        """
            Get customer infos

            :param str customer_id: The reference to the customer
            :return: A `cerberus.services.crm.base.DefendantClass` instance
            :rtype: `cerberus.services.crm.base.DefendantClass`
            :raises `cerberus.services.crm.base.CRMServiceException`: if error
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_service_infos(self, service_id):
        """
            Get service infos

            :param str service_id: The reference to the service
            :return: A `cerberus.services.crm.base.ServiceClass` instance
            :rtype: `cerberus.services.crm.base.ServiceClass`
            :raises `cerberus.services.crm.base.CRMServiceException`: if error
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_customer_revenue(self, customer_id, *args, **kwargs):
        """
            Get customer revenue
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )

    @abc.abstractmethod
    def get_customer_services(self, customer_id):
        """
            Get all services for given customer.

            Cerberus is expecting this kind of struct :

            [
                {
                    'zone': 'EMEA'
                    'services': [
                        {
                            'name': 'test',
                            'reference': 'vps.test',
                            'componentType': 'VPS',
                            'creationDate': 1452686304,
                            'expirationDate': 1453686304,
                            'state': 'active',
                        },
                    ...
                    ]
                },
            ...
            ]

            :param str customer_id: The reference to the customer
            :return: The list of services
            :rtype: list
            :raises `cerberus.services.crm.base.CRMServiceException`
        """
        cls = self.__class__.__name__
        func = inspect.stack()[0][3]

        raise NotImplementedError(
            "'{}' instance does not implement method '{}'".format(cls, func)
        )


###
#
#     DefendantClass example:
#
#     {
#         'customerId': 'john.doe.5',  # customer uuid in internal CRM/DB
#         'email': 'john.doe@example.com',
#         'spareEmail': 'backup@domain.tld',
#         'firstname': 'John',
#         'name': 'Doe',
#         'country': 'FR',
#         'billingCountry': 'FR',
#         'address': '1 rue de la mer',
#         'city': 'Paris',
#         'zip': '75016',
#         'phone': '+33123456789',
#         'lang': 'FR',
#         'legalForm': 'individual' ('corporation', 'individual' ...),
#         'organisation': None,
#         'creationDate': datetime.datetime(2010, 01, 01, 0, 0),
#         'isVIP': False,
#         'isInternal': False,  (can be an internal customer)
#         'state': 'active',  ('closed', 'blocked' ...)
#     }
###


class DefendantClass(dict):
    """
        Customer dynamic dict mapping (syntactic sugar)
    """

    fields = DefendantRevision.get_fields() + ["customerId"]

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        if name in self.fields:
            try:  # Try to convert internal CRM/API/DB datetime format
                self[name] = datetime.strptime(value, "%Y-%m-%d %X").timetuple()
                self[name] = int(mktime(self[name]))
            except (TypeError, ValueError):
                self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)


###
#
#    Service example:
#
#    {
#        'serviceId': '123456',  # reference service uuid in internal CRM/DB
#        'name': 'example',
#        'domain': 'www.example.com',
#        'componentType': 'HOSTING',
#        'componentSubType': 'WEB',
#        'reference': 'hosting.pro.2016',
#    }
###


class ServiceClass(dict):
    """
        Service dynamic dict mapping (syntactic sugar)
    """

    fields = Service.get_fields()

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        if name in self.fields:
            try:  # Try to convert internal CRM/API/DB datetime format
                self[name] = datetime.strptime(value, "%Y-%m-%d %X").timetuple()
                self[name] = int(mktime(self[name]))
            except (TypeError, ValueError):
                self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)
