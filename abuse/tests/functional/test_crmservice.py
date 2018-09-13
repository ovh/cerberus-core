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
    Unit tests for customer dao default implementation
"""

from ...services.crm import CRMService
from ...services.crm.base import CRMServiceException
from ...tests.setup import CerberusTest


class TestDefaultCustomerDaoImpl(CerberusTest):
    """
        Unit tests for customer dao service
    """
    def test_success_get_services_from_items(self):
        """
            Test success of main DAO function, identify customer
        """
        services = CRMService.get_services_from_items(ips=['1.2.3.4'])
        self.assertEqual(1, len(services))
        self.assertIn('service', services[0])
        self.assertIn('defendant', services[0])
        self.assertIn('items', services[0])
        self.assertEqual('Doe', services[0]['defendant']['name'])
        self.assertIn('1.2.3.4', services[0]['items']['ips'])

    def test_fail_get_services_from_items(self):
        """
            Test fail of main DAO function, identify customer
        """
        services = CRMService.get_services_from_items()
        self.assertEqual(0, len(services))
        services = CRMService.get_services_from_items(ips=['8.8.8.8'])
        self.assertEqual(1, len(services))

    def test_get_customer_infos(self):
        """
            Test get_customer_infos
        """
        defendant = CRMService.get_customer_infos('john.doe.42')
        self.assertEqual('Doe', defendant.name)
        self.assertRaises(CRMServiceException, lambda: CRMService.get_customer_infos('john.doe.43'))

    def test_get_service_infos(self):
        """
            Test get_service_infos
        """
        service = CRMService.get_service_infos('123456')
        self.assertEqual('example', service.name)
        self.assertRaises(CRMServiceException, lambda: CRMService.get_customer_infos('654321'))
