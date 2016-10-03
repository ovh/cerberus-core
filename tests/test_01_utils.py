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
    Unit test for utils
"""

from django.test import TestCase
from mock import patch
from requests import Response

from utils import utils


class GlobalTestCase(TestCase):
    """
        Global setUp for tests
    """
    def setUp(self):
        pass

    def tearDown(self):
        pass


class TestUtils(GlobalTestCase):
    """
        Unit tests for utils
    """

    def setUp(self):

        self._gethostbyname_ex_return = ('mock', 'mock', ['127.0.0.1'])
        self._gethostbyname_return = '127.0.0.1'
        self._gethostbyaddr_return = 'ovh.com'

    def test_success_1_get_url_hostname(self):

        url = 'https://www.ovh.com'
        hostname = utils.get_url_hostname(url)
        self.assertEqual('www.ovh.com', hostname)

    def test_success_2_get_url_hostname(self):

        url = 'ftps://www.ovh.com/test.fr'
        hostname = utils.get_url_hostname(url)
        self.assertEqual('www.ovh.com', hostname)

    def test_fail_get_url_hostname(self):

        url = 'ftpseoiapze:/itopze/www.ovh.com/test.fr'
        hostname = utils.get_url_hostname(url)
        self.assertEqual(None, hostname)

    def test_ambiguous_get_url_hostname(self):

        url = 'www.ovh.com/test.fr'
        hostname = utils.get_url_hostname(url)
        self.assertEqual(None, hostname)

    @patch('socket.gethostbyname_ex')
    def test_success_get_ips_from_url(self, socket_mock):

        socket_mock.return_value = self._gethostbyname_ex_return
        url = 'http://www.ovh.com/test'
        ips = utils.get_ips_from_url(url)
        self.assertIn('127.0.0.1', ips)

    @patch('socket.gethostbyname_ex')
    def test_fail_1_get_ips_from_url(self, socket_mock):

        socket_mock.return_value = self._gethostbyname_ex_return
        url = 'www.ovh.com/test'
        ips = utils.get_ips_from_url(url)
        self.assertEqual(None, ips)

    def test_fail_2_get_ips_from_url(self):

        url = 'ovh'
        ips = utils.get_ips_from_url(url)
        self.assertEqual(None, ips)

    @patch('socket.gethostbyname_ex')
    def test_success_get_ips_from_fqdn(self, socket_mock):

        socket_mock.return_value = self._gethostbyname_ex_return
        url = 'www.ovh.com'
        ips = utils.get_ips_from_fqdn(url)
        self.assertIn('127.0.0.1', ips)

    @patch('socket.gethostbyname_ex')
    def test_fail_1_get_ips_from_fqdn(self, socket_mock):

        socket_mock.return_value = self._gethostbyname_ex_return
        url = 'www.ovh.com/test'
        ips = utils.get_ips_from_fqdn(url)
        self.assertIn('127.0.0.1', ips)

    def test_fail_2_get_ips_from_fqdn(self):

        url = 'ovh.aze'
        ips = utils.get_ips_from_fqdn(url)
        self.assertEqual(None, ips)

    def test_fail_get_reverses(self):

        reverses = utils.get_reverses_for_item('ovh')
        self.assertEqual(1, len(reverses))
        reverses = utils.get_reverses_for_item('ovh', nature='IP')
        self.assertEqual(1, len(reverses))
        reverses = utils.get_reverses_for_item('ovh.aze', nature='test')
        self.assertEqual(2, len(reverses))
        reverses = utils.get_reverses_for_item('ovh.fr', nature='IP')
        self.assertEqual(1, len(reverses))
        reverses = utils.get_reverses_for_item('ovh.fr', nature='URL')
        self.assertEqual(1, len(reverses))

    @patch('socket.gethostbyname')
    @patch('socket.gethostbyaddr')
    def test_successl_get_reverses(self, byname_mock, byaddr_mock):

        byname_mock.return_value = self._gethostbyname_return
        byaddr_mock.return_value = self._gethostbyaddr_return
        reverses = utils.get_reverses_for_item('ovh.com', nature='FQDN')
        self.assertEqual(3, len(reverses))
        self.assertIn('fqdnResolved', reverses)
        self.assertEqual('ovh.com', reverses['fqdnResolved'])

    def test_dehtmlify(self):

        # No need to cover all html2text lib
        content = '<html><body>test\r\ntest<img src ...../></body></html>'
        content = utils.dehtmlify(content)
        self.assertIn('test', content)
        self.assertNotIn('img', content)
        self.assertNotIn('<', content)

    @patch('requests.get')
    def test_request_wrapper(self, mock_urlopen):

        mocked_response = Response()
        mocked_response.status_code = 500
        mock_urlopen.return_value = mocked_response
        self.assertRaises(utils.RequestException, lambda: utils.request_wrapper('https://www.ovh.com', method='GET'))
