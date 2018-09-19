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
    Default Implementation of Customer DAO

"""
from datetime import datetime

from netaddr import IPAddress

from .base import CRMServiceBase, CRMServiceException, DefendantClass, ServiceClass
from ...utils import networking

JOHN_DOE = {
    "email": "john.doe@example.com",
    "customerId": "john.doe.42",
    "firstname": "John",
    "name": "Doe",
    "city": "Paris",
    "country": "FR",
    "address": "1 rue de la mer",
    "legalForm": "individual",
    "zip": "75000",
    "lang": "FR",
    "creationDate": datetime.fromtimestamp(1444336416),
    "state": "active",
}

DEFAULT_SERVICE = {
    "serviceId": "123456",
    "name": "example",
    "domain": "www.example.com",
    "componentType": "HOSTING",
    "componentSubType": "WEB",
    "reference": "hosting.pro.2016",
}

SERVICES = {"john.doe.42": [DEFAULT_SERVICE]}


class DefaultCRMService(CRMServiceBase):
    """
        Default, numb, implementation of CustomerDaoBase
    """

    def __init__(self, config, logger=None):
        pass

    def get_services_from_items(self, ips=None, urls=None, fqdn=None):
        """
            Map service/defendant for given items (provided by cerberus parser)

            :param list ips: List of IP address.
            :param list urls: List of URLs.
            :param list fqdn: List of fqdn
            :return: The result of the parsing of given items
            :rtype: dict
            :raises `cerberus.services.crm.base.CRMServiceException`: if error
        """
        response = []
        if ips:  # Totally absurd example, just keep managed and public IPs
            ips = [
                ip
                for ip in ips
                if networking.get_ip_network(ip) == "managed"
                and not IPAddress(ip).is_private()
            ]
            if ips:
                response = get_default_struct(
                    ServiceClass(DEFAULT_SERVICE),
                    DefendantClass(**JOHN_DOE),
                    ips=ips,
                    urls=[],
                    fqdn=[],
                )
        elif urls:
            if "http://www.cdnproxy-protected-domain.com/testcdn" not in urls:
                response = get_default_struct(
                    ServiceClass(DEFAULT_SERVICE),
                    DefendantClass(**JOHN_DOE),
                    ips=[],
                    urls=urls,
                    fqdn=[],
                )
        elif fqdn:
            response = get_default_struct(
                ServiceClass(DEFAULT_SERVICE),
                DefendantClass(**JOHN_DOE),
                ips=[],
                urls=[],
                fqdn=fqdn,
            )

        return response

    def get_customer_infos(self, customer_id):
        """
            Get customer infos

            :param str customer_id: The reference to the customer
            :return: A `cerberus.services.crm.base.DefendantClass` instance
            :rtype: `cerberus.services.crm.base.DefendantClass`
            :raises `cerberus.services.crm.base.CRMServiceException`: if error
        """
        if customer_id == JOHN_DOE["customerId"]:
            return DefendantClass(**JOHN_DOE)
        else:
            raise CRMServiceException("Customer not found")

    def get_service_infos(self, service_id):
        """
            Get service infos

            :param str service_id: The reference to the service
            :return: A `cerberus.services.crm.base.ServiceClass` instance
            :rtype: `cerberus.services.crm.base.ServiceClass`
            :raises `cerberus.services.crm.base.CRMServiceException`: if error
        """
        if service_id == DEFAULT_SERVICE["serviceId"]:
            return ServiceClass(**DEFAULT_SERVICE)
        else:
            raise CRMServiceException("Customer not found")

    def get_customer_services(self, customer_id):
        """
            Get all services for given customer.

            Cerberus is expecting this kind of struct :

            [{
                'zone': 'EMEA',
                'services': [{
                    'name': 'test',
                    'reference': 'vps.test',
                    'componentType': 'VPS',
                    'creationDate': 1452686304,
                    'expirationDate': 1453686304,
                    'state': 'active',
                }],
            }]

            :param str customer_id: The reference to the customer
            :return: The list of services
            :rtype: list
            :raises `cerberus.services.crm.base.CRMServiceException`: if error
        """
        if customer_id != JOHN_DOE["customerId"]:
            raise CRMServiceException("Customer not found")

        response = [{"zone": "EMEA", "services": SERVICES[JOHN_DOE["customerId"]]}]
        return response

    def get_customer_revenue(self, customer_id, *args, **kwargs):

        return 0


def get_default_struct(service, defendant, ips=None, urls=None, fqdn=None):
    """
        Init returned struct
    """
    return [
        {
            "service": service,
            "defendant": defendant,
            "items": {
                "ips": set(ips) if ips else set(),
                "urls": set(urls) if urls else set(),
                "fqdn": set(fqdn) if fqdn else set(),
            },
        }
    ]
