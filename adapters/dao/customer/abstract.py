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
from datetime import datetime
from time import mktime

from django.conf import settings

from abuse.models import DefendantRevision, Service

DEFENDANT_REVISION_FIELDS = [f.name for f in DefendantRevision._meta.fields]
DEFENDANT_REVISION_FIELDS.extend(('customerId',))
SERVICE_FIELDS = [f.name for f in Service._meta.fields]
FORMAT = settings.GENERAL_CONFIG['customer_dao_datetime_format']


class CustomerDaoException(Exception):
    """ Exception that must be raised by CustomerDao implementations to ensure error are correctly handled.

        .. py:class:: CustomerDaoException
    """
    def __init__(self, message):
        super(CustomerDaoException, self).__init__(message)


class CustomerDaoBase(object):
    """ Abstract class defining a tuple Customer/Service DAO. For example, an implementation might get those data
        in an CRM, RDBMS, or API.

        The only exception allowed to be raised is ..py:exception:: CustomerDaoException

        Do the magic with your own implementation, BUT cerberus parser is expecting this kind of struct

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
                'service': ServiceCalss(),
                'defendant': 'DefendantClass(),
                'items': {
                    'ips': None,
                    'urls': set(['https://www.example.com/offending/content']),
                    'fqdn': None,
                },
            },
            ...
        ]

        or [] if nothing match.

        Ex:
            print get_services_from_items(ips=['1.1.1.1','2.2.2.2'], urls=['https://2.2.2.2/phishing.html'])

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
                        'customerId': 'mr.robot.A46Z',  # reference to customer uid in enterprise CRM/DB
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
                        'customerId': 'john.doe.123456',  # reference to customer uid in enterprise CRM/DB
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
            :raises `adapters.dao.customer.abstract.CustomerDaoException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_services_from_items'" % (cls))

    @abc.abstractmethod
    def get_customer_infos(self, customer_id):
        """
            Get customer infos

            :param str customer_id: The reference to the customer
            :return: A `adapters.dao.customer.abstract.DefendantClass` instance
            :rtype: `adapters.dao.customer.abstract.DefendantClass`
            :raises `adapters.dao.customer.abstract.CustomerDaoException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_customer_infos'" % (cls))

    @abc.abstractmethod
    def get_service_infos(self, service_id):
        """
            Get service infos

            :param str service_id: The reference to the service
            :return: A `adapters.dao.customer.abstract.ServiceClass` instance
            :rtype: `adapters.dao.customer.abstract.ServiceClass`
            :raises `adapters.dao.customer.abstract.CustomerDaoException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_service_infos'" % (cls))

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
            :raises `adapters.dao.customer.abstract.CustomerDaoException`: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_customer_services'" % (cls))


###
#     A DefendantClass : (see abuse.models to customize your DEFENDANT_REVISION_FIELDS)
#
#     E.g:
#
#     {
#         'customerId': 'john.doe.123456',  # reference to customer uid in enterprise CRM/DB
#         'email': 'john.doe@example.com',  <-- REVISION_FIELDS (actual infos in your enterprise CRM/DB)
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
    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        if name in DEFENDANT_REVISION_FIELDS or name == 'customerId':
            try:  # Try to convert exported (from internal CRM/API/DB) datetime info format to timestamp
                self[name] = int(mktime(datetime.strptime(value, FORMAT).timetuple()))
            except (TypeError, ValueError):
                self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)


###
#    A Service : (see abuse.models to customize your SERVICE_FIELDS)
#
#    E.g:
#
#    {
#        'serviceId': '123456',  # reference to service uid in enterprise CRM/DB
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
    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        if name in SERVICE_FIELDS:
            try:  # Try to convert exported (from internal CRM/API/DB) datetime info format to timestamp
                self[name] = int(mktime(datetime.strptime(value, FORMAT).timetuple()))
            except (TypeError, ValueError):
                self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)
